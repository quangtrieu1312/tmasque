package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"golang.org/x/sys/unix"
	"syscall"
	"os/signal"
	"runtime"
	_ "net/http/pprof"
	
	connectip "github.com/quic-go/connect-ip-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"

	"github.com/quangtrieu1312/tmasque/config"
	"github.com/quangtrieu1312/tmasque/constants"
	"github.com/quangtrieu1312/tmasque/logger"
	"github.com/quangtrieu1312/tmasque/utility"
)

// delAllTable9000Rules removes EVERY `ip rule` entry pointing at table 9000.
// A single `ip rule del` removes only ONE match, but entries accumulate: each
// connection attempt calls Bootstrap (which adds one) and the retry loop can run
// it several times, plus an unclean prior exit can leave stale entries. So we
// loop until `ip rule del` fails (no more matching rule). Best-effort — a failure
// just means there's nothing left to delete, never fatal.
func delAllTable9000Rules() {
    for i := 0; i < 64; i++ {
        if err := exec.Command("/sbin/ip", "rule", "del", "table", "9000").Run(); err != nil {
            break
        }
    }
}

// enforceBBR sets the host's default TCP congestion control to BBR when available.
// The inner TCP flows the tunnel carries belong to the host's apps, not to tmasque,
// so the only lever on their CC is the system default — set it here at startup.
// BBR is rate/RTT-based and tolerates the small non-congestive loss/reorder a
// userspace tunnel injects, which collapses loss-based CUBIC (P1-up 38→432 measured;
// the path-level effect helps any tunnel, but it's the right CC for tunnel transport
// and only affects flows ORIGINATING on this host — i.e. the upload sender). Best
// effort and non-fatal: missing module / restricted /proc just logs and continues.
// Override with TCP_CC (e.g. TCP_CC=cubic to disable, TCP_CC=off to skip entirely).
func enforceBBR(ctx context.Context) {
    cc := "bbr"
    if v, _ := ctx.Value("TCP_CC").(string); v != "" {
        if strings.EqualFold(v, "off") || strings.EqualFold(v, "none") {
            return
        }
        cc = strings.ToLower(v)
    }
    // Load the module if it isn't built in (ignore errors — may be builtin or denied).
    _ = exec.Command("/sbin/modprobe", "tcp_"+cc).Run()
    avail, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
    if err != nil {
        logger.LogInfo(fmt.Sprintf("TCP CC: cannot read available algorithms (%v); leaving system default", err))
        return
    }
    if !containsField(string(avail), cc) {
        logger.LogInfo(fmt.Sprintf("TCP CC: %q not available (have: %s); leaving system default", cc, strings.TrimSpace(string(avail))))
        return
    }
    if err := os.WriteFile("/proc/sys/net/ipv4/tcp_congestion_control", []byte(cc), 0644); err != nil {
        logger.LogInfo(fmt.Sprintf("TCP CC: failed to set %q (%v); leaving system default", cc, err))
        return
    }
    logger.LogInfo(fmt.Sprintf("TCP CC: host default set to %q for tunnel-tolerant single-stream throughput", cc))
}

// containsField reports whether space-separated list s contains the exact token tok.
func containsField(s, tok string) bool {
    for _, f := range strings.Fields(s) {
        if f == tok {
            return true
        }
    }
    return false
}

// udpBufTarget is the UDP socket buffer ceiling we want for the QUIC transport.
// quic-go requests ~7 MB via SO_RCVBUF/SO_SNDBUF but the kernel silently caps the
// request at net.core.{r,w}mem_max, whose stock default is ~208 KB. A 208 KB rcvbuf
// overflows on bursts → the kernel drops UDP packets → loss that is survivable for
// 100 multiplexed flows but FATAL to a single stream (its cwnd collapses). Raising
// the ceiling lets quic-go's buffer request actually take effect. 7.5 MB.
const udpBufTarget = 7864320

// raiseSysctl raises a /proc/sys value to target if it is currently lower. Raise
// only (never lowers a host that's already tuned higher) and best-effort: a missing
// path or a read-only /proc (restricted container) just logs and continues.
func raiseSysctl(key string, target int) {
    path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
    cur := 0
    if b, err := os.ReadFile(path); err == nil {
        cur, _ = strconv.Atoi(strings.TrimSpace(string(b)))
    }
    if cur >= target {
        return
    }
    if err := os.WriteFile(path, []byte(strconv.Itoa(target)), 0644); err != nil {
        logger.LogInfo(fmt.Sprintf("sysctl %s: could not raise to %d (%v); leaving %d", key, target, err, cur))
        return
    }
    logger.LogInfo(fmt.Sprintf("sysctl %s: %d -> %d (UDP buffer for QUIC transport)", key, cur, target))
}

// tuneUDPBuffers raises the UDP socket buffer ceilings so quic-go's large-buffer
// request isn't silently clamped to the stock ~208 KB (see udpBufTarget). Only the
// _max ceilings are touched — quic-go sets SO_RCVBUF/SO_SNDBUF explicitly, so the
// per-socket defaults need not change (avoids bloating every socket on the host).
func tuneUDPBuffers() {
    raiseSysctl("net.core.rmem_max", udpBufTarget)
    raiseSysctl("net.core.wmem_max", udpBufTarget)
}

func Bootstrap(ctx context.Context) {
    logger.LogInfo("Exec bootstrap")
    // Optimise the host stack for carrying flows over a userspace QUIC tunnel.
    enforceBBR(ctx)
    tuneUDPBuffers()
    // Clear any stale/duplicate table-9000 rules first so repeated attempts or a
    // prior unclean exit can't accumulate them.
    delAllTable9000Rules()
    cmd := exec.Command("/sbin/ip", "rule", "add", "not", "fwmark", ctx.Value("FWMARK").(string), "table", "9000")
    logger.LogInfo("Running command: /sbin/ip rule add not fwmark <FWMARK> table 9000")
    _, err := cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Error running pre up command: %v", err))
    }
}

func RunPostUp(ctx context.Context) {
    logger.LogInfo("Exec post up")
	enableStatsStr, _ := ctx.Value("ENABLE_STATISTIC").(string)
	enableStats, _ := strconv.ParseBool(enableStatsStr)
	if enableStats {
		go http.ListenAndServe("localhost:9484", nil)
	}
}

func GracefullyShutdown() {
    logger.LogInfo("Exec post down")
    // Delete ALL table-9000 rules (loop), not just one — and never fatal, since
    // shutdown can run twice (signal handler + run loop) and the second pass /
    // an already-clean state must not abort us before the table flush.
    logger.LogInfo("Deleting all ip rule entries for table 9000")
    delAllTable9000Rules()
    logger.LogInfo("Flushing routing table 9000")
    if err := exec.Command("/sbin/ip", "route", "flush", "table", "9000").Run(); err != nil {
        logger.LogInfo(fmt.Sprintf("table 9000 flush: %v (ok if already empty)", err))
    }
}

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
	sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan,
        syscall.SIGHUP,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGQUIT)
	go func() {
    	<-sigChan
    	GracefullyShutdown()
    	cancel()
	}()
    config.Load(&ctx)
    logLevel := ctx.Value("LOG_LEVEL").(string)
    logPath := constants.LOG_PATH
    logger.UpdateLogLevelName(logLevel)
    logger.UpdateLogPath(logPath)
    f, err := os.OpenFile(logger.GetLogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    } else {
        wrt := io.MultiWriter(os.Stdout, f)
        log.SetOutput(wrt)
    }
    defer f.Close()
    serverInfo := ctx.Value("SERVER").(string)
    serverHost := serverInfo
    serverPort := 443
    if portIndex := strings.Index(serverInfo, ":"); portIndex > -1 {
        host := serverInfo[:portIndex]
        port, err := strconv.Atoi(serverInfo[portIndex+1:])
        if err != nil {
		    logger.LogFatal(fmt.Sprintf("Failed to parse server port: %v", err))
            os.Exit(1)
        }
        serverHost = host
        serverPort = port
    }
    var serverIp netip.Addr
    if ip, err := netip.ParseAddr(serverHost); err != nil {
        logger.LogDebug(fmt.Sprintf("Resolving %v", serverHost))
        if ips, err := net.LookupIP(serverHost); err != nil {
            logger.LogFatal(fmt.Sprintf("Failed to resolve server FQDN: %v", err))
            os.Exit(1)
        } else {
            serverIp = netip.MustParseAddr(ips[0].String())
        }
    } else {
        serverIp = ip
    }
    ctx = context.WithValue(ctx, "SERVER_IP", serverIp.String())
    logger.LogInfo(fmt.Sprintf("Connecting to %v", serverIp))
	serverAddr := netip.AddrPortFrom(serverIp, uint16(serverPort))
    enableKeyLog, err := strconv.ParseBool(ctx.Value("ENABLE_KEY_LOG").(string))
    if err != nil {
		logger.LogError(fmt.Sprintf("Cannot parse ENABLE_KEY_LOG config, default to `false`"))
        enableKeyLog = false
    }
    keyLogPath := ctx.Value("KEY_LOG_PATH").(string)
    errChan := make(chan error)
    isRunningChan := make(chan bool)
    go func(contxt context.Context) {
        for {
            select {
            case cerr := <-errChan:
                logger.LogError(fmt.Sprintf("Encounter error: %v", cerr))
                cancel()
                return
            case isRunning := <- isRunningChan:
                if (isRunning) {
                    logger.LogInfo("Masque is up")
                    RunPostUp(contxt)
                } else {
                    logger.LogInfo("Masque is down")
                    GracefullyShutdown()
                    cancel()
                	return
                }
            }
        }
    }(ctx)
    tunnelCount := 4
    if v := ctx.Value("TUNNEL_COUNT"); v != nil {
        if n, perr := strconv.Atoi(v.(string)); perr == nil && n > 0 {
            tunnelCount = n
        }
    }
    logger.LogInfo(fmt.Sprintf("Bonding %d parallel tunnels", tunnelCount))
    go func(contxt context.Context) {
        // Reconnect policy. A VPN client must NOT self-terminate on network trouble — a
        // merely-lossy/jittery outer leg, or a transient server blip, should drive a
        // reconnect, never a process exit. The old code incremented a single `attempt`
        // counter on EVERY establish-failure AND every runtime drop, NEVER reset it, and
        // exited via "Out of attempts" → cancel() after just 3 cumulative errors over the
        // whole session — so on any flaky network the client eventually killed itself,
        // tun0 vanished, and throughput went to a hard 0 (WireGuard, by contrast, retries
        // forever). Fix: retry indefinitely with capped exponential backoff; reset the
        // backoff whenever a connection has been stably up, so transient drops recover
        // instantly and only a genuinely-unreachable server backs off (it never gives up).
        backoff := time.Second
        const maxBackoff = 15 * time.Second
        const stableUptime = 10 * time.Second
        for {
	        conns, devs, err := establishAllTunnels(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath, tunnelCount)
	        if err != nil {
                logger.LogError(fmt.Sprintf("Failed to establish bonded MASQUE tunnels: %v (retry in %v)", err, backoff))
                select {
                case <-ctx.Done():
                    return
                case <-time.After(backoff):
                }
                backoff = min(backoff*2, maxBackoff)
                continue
	        }
            backoff = time.Second // connected — reset backoff
	        logger.LogDebug(fmt.Sprintf("Created TUN device: %s with %d bonded tunnels", devs[0].Name(), len(conns)))
            upTime := time.Now()
            eChan := make(chan error, runtime.NumCPU() + tunnelCount + 1)
			connCtx, connCancel := context.WithCancel(ctx)
            go func() {
                cerr := <-eChan
                logger.LogError(fmt.Sprintf("Tunneling error: %v", cerr))
				connCancel()
				for _, c := range conns {
					c.Close()
				}
				for _, dev := range devs {
					dev.Close()
				}
            }()
            tunnel(connCtx, conns, devs, isRunningChan, eChan)
            // tunnel() returned ⇒ the connection dropped. If it had been stably up, treat
            // the drop as transient and reconnect immediately; otherwise back off.
            if ctx.Err() != nil {
                return
            }
            if time.Since(upTime) < stableUptime {
                select {
                case <-ctx.Done():
                    return
                case <-time.After(backoff):
                }
                backoff = min(backoff*2, maxBackoff)
            }
        }
    }(ctx)
    <-ctx.Done()
}

func healthCheck(ctx context.Context) error {
	//TODO
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    return nil
}

func establishMASQUEConn(ctx context.Context, serverAddr netip.AddrPort, serverFQDN string, enableKeyLog bool, keyLogPath string, tunIdx, tunCount int) ([]connectip.IPRoute, []netip.Prefix, *connectip.Conn, error) {
    fwmark, err := strconv.ParseInt(ctx.Value("FWMARK").(string), 10, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse FWMARK config to number: %w", err)
	}
	lc := net.ListenConfig{
    	Control: func(network, addr string, c syscall.RawConn) error {
        	var soErr error
        	err := c.Control(func(fd uintptr) {
            	soErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
        	})
        	if err != nil {
            	return err
        	}
        	return soErr
    	},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}

    // load tls configuration
    CertFilePath := constants.CLIENT_CERT_PATH
    KeyFilePath := constants.CLIENT_KEY_PATH
    CACertFilePath := constants.SERVER_CA_PATH
	cert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
        panic(fmt.Sprintf("Cannot load client key pair: %v",err))
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
        panic(fmt.Sprintf("Cannot create cert pool: %v", err))
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
        panic(fmt.Sprintf("Cannot read CA cert file: %v", err))
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("Invalid cert in CA PEM")
	}
    tlsConf :=  &tls.Config {
		ServerName:         serverFQDN,
		NextProtos:         []string{http3.NextProtoH3},
        RootCAs:            certPool,
		Certificates:       []tls.Certificate{cert},
    }
    if enableKeyLog {
        keyLogPath := ctx.Value("KEY_LOG_PATH").(string)
        if keyLogPath == "" {
		    logger.LogError(fmt.Sprintf("Cannot parse KEY_LOG_PATH config, default to `keys.txt`"))
            keyLogPath = "keys.txt"
        }
        keyLog, err := os.Create(keyLogPath)
	    defer keyLog.Close()
	    if err != nil {
		    logger.LogError(fmt.Sprintf("failed to create key log file: %v", err))
	    }
        tlsConf.KeyLogWriter = keyLog
    }
	dialCtx, dialCancel := context.WithTimeout(ctx, 1*time.Second)
	defer dialCancel()
	conn, err := quic.Dial(
		dialCtx,
		udpConn,
		&net.UDPAddr{IP: serverAddr.Addr().AsSlice(), Port: int(serverAddr.Port())},
		tlsConf,
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1400,
            MaxIdleTimeout:  30 * time.Second,
            KeepAlivePeriod: 10 * time.Second,
			InitialStreamReceiveWindow:     10 * 1024 * 1024,  // 10 MB
    		MaxStreamReceiveWindow:         10 * 1024 * 1024,  // 10 MB
    		InitialConnectionReceiveWindow: 15 * 1024 * 1024,  // 15 MB
    		MaxConnectionReceiveWindow:     15 * 1024 * 1024,  // 15 MB
    		// Per-connection qlog (CWND/RTT/loss) — active only when QLOGDIR is set.
    		Tracer: qlog.DefaultConnectionTracer,
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://tmasqued:%d/vpn", serverAddr.Port()))
	// Bonded-tunnel coordinates (Model A): the server uses these to slot this
	// tunnel into the client's session group and to symmetric-hash return flows.
	hdrs := http.Header{
		"Tmasqued-Tunnel-Index": []string{strconv.Itoa(tunIdx)},
		"Tmasqued-Tunnel-Count": []string{strconv.Itoa(tunCount)},
	}
	ipconn, rsp, err := connectip.DialWithHeaders(dialCtx, hconn, template, hdrs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	logger.LogDebug(fmt.Sprintf("connected to VPN server: %s", serverAddr))

	routes, err := ipconn.Routes(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get routes: %w", err)
	}
	localPrefixes, err := ipconn.LocalPrefixes(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get local prefixes: %w", err)
	}

	return routes, localPrefixes, ipconn, nil
}

// establishAllTunnels brings up N bonded tunnels to the server. Tunnel 0 is
// opened first and its assigned inner IP/routes configure the shared TUN
// device; tunnels 1..N-1 then attach to the same inner IP (the server assigns
// it idempotently per client cert). All-or-nothing: any failure tears down
// what was opened so the caller can retry cleanly.
func establishAllTunnels(ctx context.Context, serverAddr netip.AddrPort, serverHost string, enableKeyLog bool, keyLogPath string, count int) ([]*connectip.Conn, []*water.Interface, error) {
    conns := make([]*connectip.Conn, 0, count)

    routes, localPrefixes, ipconn0, err := establishMASQUEConn(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath, 0, count)
    if err != nil {
        return nil, nil, fmt.Errorf("tunnel 0: %w", err)
    }
    conns = append(conns, ipconn0)

    devs, derr := establishTunTapAndRoutes(ctx, routes, localPrefixes)
    if derr != nil {
        ipconn0.Close()
        return nil, nil, fmt.Errorf("TUN/routes setup: %w", derr)
    }

    for i := 1; i < count; i++ {
        _, _, ipconn, err := establishMASQUEConn(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath, i, count)
        if err != nil {
            for _, c := range conns {
                c.Close()
            }
            for _, d := range devs {
                d.Close()
            }
            return nil, nil, fmt.Errorf("tunnel %d: %w", i, err)
        }
        conns = append(conns, ipconn)
    }
    return conns, devs, nil
}

func establishTunTapAndRoutes(ctx context.Context, routes []connectip.IPRoute, localPrefixes []netip.Prefix) ([]*water.Interface, error) {
    // Number of MultiQueue TUN fds / reader goroutines. Default = NumCPU, but the
    // kernel's per-packet queue selection lets a single inner flow's packets land
    // on different queues, and the reader goroutines then race to WritePacket the
    // same QUIC connection — reordering that flow. Inner TCP punishes reorder
    // (spurious fast-retransmit → cwnd collapse), wrecking single-stream
    // throughput. Set TUN_QUEUES=1 for strict per-flow ordering (mirrors the
    // server's TUN_QUEUES=1 fix). Aggregate (many flows) has headroom to spare.
    numQueues := runtime.NumCPU()
    if v := ctx.Value("TUN_QUEUES"); v != nil {
        if n, perr := strconv.Atoi(v.(string)); perr == nil && n > 0 {
            numQueues = n
        }
    }
    // TUN_GSO=true enables IFF_VNET_HDR + TSO so the kernel hands coalesced
    // GSO super-frames per read; water splits them into MTU packets. Cuts the
    // per-packet read-syscall rate and lets a single flow's packets burst
    // through the encap→datagram→send pipeline together (amortizing per-packet
    // goroutine-handoff latency, the WireGuard-go technique).
    gso := false
    if v := ctx.Value("TUN_GSO"); v != nil {
        gso = v.(string) == "true"
    }
    devs := make([]*water.Interface, numQueues)
	// First device — let OS assign name
	var err error
	devs[0], err = water.New(water.Config{
    	DeviceType: water.TUN,
    	PlatformSpecificParams: water.PlatformSpecificParams{
        	MultiQueue: true,
        	GSO:        gso,
    	},
	})
	if err != nil {
    	return nil, fmt.Errorf("failed to create TUN device queue 0: %w", err)
	}
	devName := devs[0].Name()
	// Subsequent queues — MUST use same name
	for i := 1; i < numQueues; i++ {
    	dev, err := water.New(water.Config{
        	DeviceType: water.TUN,
        	PlatformSpecificParams: water.PlatformSpecificParams{
            	Name:       devName, // same device, new fd
            	MultiQueue: true,
            	GSO:        gso,
        	},
    	})
    	if err != nil {
        	return nil, fmt.Errorf("failed to create TUN queue %d: %w", i, err)
    	}
    	devs[i] = dev
	}

    // Tunnel link MTU, read from config (TUNNEL_MTU) like the server does; default
    // 1416 to MATCH the server (the old hardcoded 1252 was below both the server's
    // 1416 and connect-ip's minMTU=1280, needlessly shrinking the client's egress MSS).
    // Per draft-ietf-masque-connect-ip the CONNECT-IP encap overhead is ≤51B; with
    // IPv4+UDP (28B) that leaves up to 1421 on a 1500 path, so 1416 is safe (verified:
    // 6/6 consistent uploads to a forwarded external target). Ops can lower it via the
    // config for client paths with a smaller real MTU. Floor 576 (IPv4 min datagram).
    mtu := 1416
    if v := ctx.Value("TUNNEL_MTU"); v != nil {
        if m, perr := strconv.ParseUint(v.(string), 10, 64); perr == nil && m >= 576 {
            mtu = int(m)
        }
    }
    // link setup only needs to happen once, on devs[0]
    link, err := netlink.LinkByName(devName)
    netlink.LinkSetMTU(link, mtu)
    if err != nil {
        return nil, fmt.Errorf("failed to get TUN interface: %w", err)
    }
    for _, p := range localPrefixes {
        if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: utility.PrefixToIPNet(p)}); err != nil {
            return nil, fmt.Errorf("failed to add address assigned by peer: %w", err)
        }
    }
    if err := netlink.LinkSetUp(link); err != nil {
        return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
    }

	for _, route := range routes {
		logger.LogDebug(fmt.Sprintf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol))
		for _, prefix := range route.Prefixes() {
            cmd := exec.Command("/sbin/ip", "route", "add", prefix.String() , "dev", devName, "table", "9000")
            logger.LogInfo(fmt.Sprintf("Adding route: %v", prefix.String()))
            _, err := cmd.Output()
            if err != nil {
                return nil, fmt.Errorf("Failed to add route: %v", err)
            }
		}
	}
    Bootstrap(ctx)
    return devs, nil
}

func tunnel(ctx context.Context, conns []*connectip.Conn, devs []*water.Interface, isRunningChan chan bool, errChan chan error) {
	n := len(conns)

	// Receiver-side per-flow resequencer. Off by default (net-negative in testing);
	// enable with FORWARD_RESEQ=true in the config.
	reseqEnabled := false
	if v, _ := ctx.Value("FORWARD_RESEQ").(string); v != "" {
		reseqEnabled, _ = strconv.ParseBool(v)
	}

	// Download pre-reseq reorder counter. Logs every 2s when ENABLE_STATISTIC is on.
	if v, _ := ctx.Value("ENABLE_STATISTIC").(string); v != "" {
		if on, _ := strconv.ParseBool(v); on {
			go func() {
				t := time.NewTicker(2 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						tot := utility.PreReseqTotal.Load()
						ooo := utility.PreReseqOOO.Load()
						pct := 0.0
						if tot > 0 {
							pct = 100 * float64(ooo) / float64(tot)
						}
						gTot := utility.PreSendTotal.Load()
						gGen := utility.PreSendGenuine.Load()
						gRetr := utility.PreSendRetr.Load()
						gPct, rPct := 0.0, 0.0
						if gTot > 0 {
							gPct = 100 * float64(gGen) / float64(gTot)
							rPct = 100 * float64(gRetr) / float64(gTot)
						}
						logger.LogInfo(fmt.Sprintf("pre-reseq: total=%d ooo=%d (%.1f%%) | genuine: %d/%d (%.2f%%) retr: %d (%.2f%%)", tot, ooo, pct, gGen, gTot, gPct, gRetr, rPct))
					}
				}
			}()
		}
	}

	// Inbound: one reader per tunnel → a TUN queue. Each tunnel's quic-go
	// connection decrypts on its own goroutine, so this parallelises across cores.
	// NOTE: with TUNNEL_COUNT=1 this single goroutine's ReadPacket (QUIC decode)
	// rate caps P100-dn at ~430 Mbit even though the server is idle — fanning the
	// tun-Write syscalls out to parallel writers did NOT help (decode, not write,
	// is the cap; verified TM_RXFANOUT). Lifting it needs faster single-conn decode
	// or multi-conn (TUNNEL_COUNT>1 regressed — TC4). Left simple/single-writer.
	for i, c := range conns {
		go func(c *connectip.Conn, id int) {
			dev := devs[id%len(devs)]
			b := make([]byte, 1500)
			// Measure reorder AS QUIC delivers it, before reseq reorders, to tell
			// transport reorder apart from reseq-introduced reorder.
			obs := utility.NewPreReseqObserver()
			genObs := utility.NewPreSendGenuineObserver()
			var out [][]byte

			// Receiver-side per-flow reorder (FORWARD_RESEQ, off by default). The
			// OCI->client leg + quic-go RX inject ~3% genuine reorder (server packer
			// 0.10% vs client pre-reseq ~3.4% at P1-dn). SINGLE-WRITER: Push (reorder)
			// + FlushExpired (idle/tail drain) both run in THIS goroutine, the only
			// dev writer (the old version flushed from a 2nd goroutine that raced
			// dev.Write and re-introduced reorder — net-negative). For an active flow
			// the gap-skip is driven by Push's window-full path; FlushExpired drains
			// only idle/tail flows. (Resequencing alone does NOT recover single-stream
			// throughput — the collapse is jitter/loss, not reorder; reseq kept off.)
			var reseq *utility.ForwardReseq
			if reseqEnabled {
				reseq = utility.NewForwardReseq(128, 5*time.Millisecond)
			}

			for {
				m, err := c.ReadPacket(b)
				if err != nil {
					select {
						case errChan <- fmt.Errorf("tunnel#%d fatal read from MASQUE: %w", id, err):
						default:
					}
					return
				}
				obs.Observe(b[:m])
				genObs.Observe(b[:m])
				if reseqEnabled {
					now := time.Now()
					out = reseq.Push(b[:m], now, out[:0])
					out = reseq.FlushExpired(now, out)
				} else {
					out = append(out[:0], b[:m])
				}
				for _, p := range out {
					if _, err := dev.Write(p); err != nil {
						select {
							case errChan <- fmt.Errorf("tunnel#%d failed to write to TUN: %w", id, err):
							default:
						}
					}
				}
			}
		}(c, i)
	}

	// Outbound: one reader per TUN queue. Each packet is pinned to a tunnel by
	// the symmetric flow hash, so the server's return traffic for that flow
	// comes back on the same tunnel (must match server flowHashSym exactly).
	for i, dev := range devs {
		go func(d *water.Interface, id int) {
			b := make([]byte, 1500)
			for {
				m, err := d.Read(b)
				if err != nil {
					select {
						case errChan <- fmt.Errorf("queue#%d fatal read from TUN: %w", id, err):
						default:
					}
					return
				}
				idx := int(flowHashSym(b[:m]) % uint32(n))
				icmp, err := conns[idx].WritePacket(b[:m])
				if err != nil {
					select {
						case errChan <- fmt.Errorf("queue#%d write to tunnel %d: %w", id, idx, err):
						default:
					}
				}
				if len(icmp) > 0 {
					if _, err := d.Write(icmp); err != nil {
						select {
							case errChan <- fmt.Errorf("queue#%d failed to write ICMP: %w", id, err):
							default:
						}
					}
				}
			}
		}(dev, i)
	}
	isRunningChan <- true
	<-ctx.Done()
}

// flowHashSym is the order-independent 5-tuple hash that pins a flow to one
// bonded tunnel. It MUST stay byte-for-byte identical to the server's
// flowHashSym (xdp/tunnel.go) so each flow's two directions pick the same
// tunnel index. See that function for the canonical-input definition.
func flowHashSym(pkt []byte) uint32 {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	srcIP := pkt[12:16]
	dstIP := pkt[16:20]
	var srcPort, dstPort uint16
	if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
		srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}

	loIP, loPort, hiIP, hiPort := srcIP, srcPort, dstIP, dstPort
	if c := bytes.Compare(srcIP, dstIP); c > 0 || (c == 0 && srcPort > dstPort) {
		loIP, loPort, hiIP, hiPort = dstIP, dstPort, srcIP, srcPort
	}

	const offset32, prime32 = 2166136261, 16777619
	h := uint32(offset32)
	upd := func(b byte) { h ^= uint32(b); h *= prime32 }
	for _, b := range loIP {
		upd(b)
	}
	upd(byte(loPort >> 8))
	upd(byte(loPort))
	for _, b := range hiIP {
		upd(b)
	}
	upd(byte(hiPort >> 8))
	upd(byte(hiPort))
	upd(proto)
	return h
}
