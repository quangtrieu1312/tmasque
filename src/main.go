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

func Bootstrap(ctx context.Context) {
    logger.LogInfo("Exec bootstrap")
    cmd := exec.Command("/sbin/ip", "rule", "add", "not", "fwmark", ctx.Value("FWMARK").(string), "table", "9000")
    logger.LogInfo(fmt.Sprintf("Running command: /sbin/ip"))
    _, err := cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Error running pre up command: %v", err))
    }
}

func RunPostUp(ctx context.Context) {
    logger.LogInfo("Exec post up")
	enablePerfMon, ok := ctx.Value("ENABLE_PERFORMANCE_MONITOR").(bool)
	if !ok {
		enablePerfMon = false
	}
	if enablePerfMon {
		go http.ListenAndServe("localhost:9484", nil)
	}
}

func GracefullyShutdown() {
    logger.LogInfo("Exec post down")
    cmd := exec.Command("/bin/bash", "-c", "ip rule del table 9000", "||", "/bin/true")
    logger.LogInfo(fmt.Sprintf("Deleting ip rule entry for table 9000"))
    _, err := cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Cannot gracefully shutdown: %v", err))
    }
    cmd = exec.Command("/bin/bash", "-c", "ip route flush table 9000", "||", "/bin/true")
    logger.LogInfo(fmt.Sprintf("Flushing routing table 9000"))
	_, err = cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Cannot gracefully shutdown: %v", err))
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
        errorThreshold := 3
        attempt := 1
        for {
            if attempt >= errorThreshold {
                errChan <- fmt.Errorf("Out of attempts")
            }
            logger.LogInfo(fmt.Sprintf("Number of retry attempts left = %d", errorThreshold - attempt))
	        conns, devs, err := establishAllTunnels(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath, tunnelCount)
	        if err != nil {
                logger.LogError(fmt.Sprintf("Failed to establish bonded MASQUE tunnels: %v", err))
                attempt++
                continue
	        }
	        logger.LogDebug(fmt.Sprintf("Created TUN device: %s with %d bonded tunnels", devs[0].Name(), len(conns)))
            eChan := make(chan error, runtime.NumCPU() + tunnelCount + 1)
			connCtx, connCancel := context.WithCancel(ctx)
            go func() {
                cerr := <-eChan
                attempt++
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
            KeepAlivePeriod: 15*time.Second,
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
    numQueues := runtime.NumCPU()
    devs := make([]*water.Interface, numQueues)
	// First device — let OS assign name
	var err error
	devs[0], err = water.New(water.Config{
    	DeviceType: water.TUN,
    	PlatformSpecificParams: water.PlatformSpecificParams{
        	MultiQueue: true,
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
        	},
    	})
    	if err != nil {
        	return nil, fmt.Errorf("failed to create TUN queue %d: %w", i, err)
    	}
    	devs[i] = dev
	}

    // link setup only needs to happen once, on devs[0]
    link, err := netlink.LinkByName(devName)
    netlink.LinkSetMTU(link, 1252)
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

	// Inbound: one reader per tunnel → a TUN queue. Each tunnel's quic-go
	// connection decrypts on its own goroutine, so this parallelises across cores.
	for i, c := range conns {
		go func(c *connectip.Conn, id int) {
			dev := devs[id%len(devs)]
			b := make([]byte, 1500)
			for {
				m, err := c.ReadPacket(b)
				if err != nil {
					select {
						case errChan <- fmt.Errorf("tunnel#%d fatal read from MASQUE: %w", id, err):
						default:
					}
					return
				}
				if _, err := dev.Write(b[:m]); err != nil {
					select {
						case errChan <- fmt.Errorf("tunnel#%d failed to write to TUN: %w", id, err):
						default:
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
