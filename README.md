# tmasque — MASQUE VPN client

`tmasque` is the client side of a userspace VPN built on **MASQUE** (IP-over-HTTP/3,
[RFC 9484 CONNECT-IP](https://datatracker.ietf.org/doc/rfc9484/)). It dials the server
over QUIC, upgrades to an HTTP/3 CONNECT-IP session authenticated with mutual TLS,
receives a `/32` and a set of routes, and tunnels matching traffic through a local TUN
device.

> Server counterpart: [`tmasqued`](https://github.com/quangtrieu1312/tmasqued) (the AF_XDP datapath + perf work).
> Umbrella repo (setup, certs, management): [`masque-vpn`](https://github.com/quangtrieu1312/masque-vpn).

---

## How it works

```
                              application traffic
                                      |     ^
                                      v     |
             +------------------------------------------------------------+
             |   TUN dev  - policy routing (fwmark / table) steers        |
             |              matched dst prefixes here, not the            |
             |              default route                                 |
             +------------------------------------------------------------+
                                      |     ^
                                      v     |   read = down,  write = up
             +------------------------------------------------------------+
             |   tmasque                                                  |
             |     read   ->  encap inner IP into a connect-ip            |
             |                context-0 QUIC DATAGRAM   (send)            |
             |     write  <-  decap inner IP from such a                  |
             |                QUIC DATAGRAM             (recv)            |
             +------------------------------------------------------------+
                                      |     ^
                                      v     |   QUIC / UDP :443, HTTP/3 CONNECT-IP, mTLS
             +------------------------------------------------------------+
             |   tmasqued (server)                       -->   WAN        |
             +------------------------------------------------------------+
```

On connect the client receives its address and routes from the server and installs them
into a dedicated routing table selected by an `fwmark` policy rule — so the tunnel's own
QUIC packets are excluded (no routing loop) while application traffic to the advertised
prefixes is steered into the TUN.

---

## Design notes

- **Outer transport: QUIC with BBR.** The tunnel's QUIC connection uses BBR congestion
  control; the *inner* traffic keeps its own end-to-end congestion control. Inner IP rides
  unreliable **QUIC DATAGRAMs** (no head-of-line blocking, no tunnel-level retransmission).
- **Reconnect & fail-open exit.** The client retries with capped exponential backoff,
  resetting its budget once a connection has been stable, so transient loss recovers
  without intervention. After `RECONNECT_ATTEMPTS` consecutive failures (default 3) it
  **exits cleanly** rather than wedging: shutdown removes its `fwmark` policy rule and
  flushes the routing table, so an unreachable server leaves the host on normal routing
  instead of blackholing it (the policy table may carry a full `0.0.0.0/0` default).
- **Inner-TCP buffer tuning.** The tunnel adds RTT (larger inner BDP); the client raises
  `tcp_wmem`/`tcp_rmem` at bootstrap so a single inner upload isn't send-buffer limited.
- **MTU.** The TUN MTU is sized to the QUIC datagram payload budget so inner packets never
  exceed it (an over-large MTU silently drops datagrams).
- **GSO/GRO-capable TUN.** Uses a `water` fork with `IFF_VNET_HDR` + offload split (gated).
- **Config & hot-reload.** Keys live in `tmasque.conf`. `LOG_LEVEL` and `ENABLE_STATISTIC`
  are hot-reloaded on save (inotify); everything else needs a restart. QUIC TLS key logging
  is off unless `KEY_LOG_PATH` is set (the file and its directory are created on connect).
  `ENABLE_STATISTIC` emits `[STATISTIC]` diagnostics and is an independent on/off channel,
  not a verbosity level.

---

## Forked dependencies (`lib/`, git submodules)

| Submodule | Forked for |
|---|---|
| `quic-go` | CC-off-aware dataplane + datagram-queue fixes shared with the server fork. |
| `connect-ip-go` | IP-packet (context-0) framing for the datagram datapath. |
| `water` | TUN with `IFF_VNET_HDR` + GSO/GRO offload split. |

---

## Build & run

```sh
./build.sh                       # outputs build/tmasque
sudo ./build/tmasque             # reads /etc/tmasque/tmasque.conf
```

Requires Linux with TUN support and `NET_ADMIN` + `NET_RAW`. The client expects its config
at `/etc/tmasque/tmasque.conf` and its certs (`ca.crt`, `client.crt`, `client.key`) under
`/etc/tmasque/certs/` — these come from the `bundle.zip` the server's `genClient` produces.
A `Vagrantfile` is included for bare-metal VM testing, and `packaging/alpine/` builds an
APK. Full config keys and the provisioning flow are documented in
[`masque-vpn`](https://github.com/quangtrieu1312/masque-vpn).

---

## Repository layout

```
src/                 main.go (dial, TUN, datagram pump), logger, ip/rand helpers
lib/                 forked submodules (quic-go, connect-ip-go, water)
build.sh             local build → build/tmasque
packaging/alpine/    APK packaging
Vagrantfile          test VM
tmasque.conf.template
```
