# tmasque — MASQUE VPN client

`tmasque` is the client side of a userspace VPN built on **MASQUE** (IP-over-HTTP/3,
[RFC 9484 CONNECT-IP](https://datatracker.ietf.org/doc/rfc9484/)). It dials the server
over QUIC, upgrades to an HTTP/3 CONNECT-IP session authenticated with mutual TLS,
receives a `/32` and a set of routes, and tunnels matching traffic through a local TUN
device.

> Server counterpart: [`tmasqued`](https://github.com/quangtrieu1312/tmasqued) — the **AF_XDP/eBPF
> datapath, the direct-vs-WireGuard-vs-tmasque benchmarks, and the perf war-stories** live there.
> Umbrella repo (setup, certs, management): [`masque-vpn`](https://github.com/quangtrieu1312/masque-vpn).

---

## How it works

```
┌─ tmasque (client) ─────────────────────┐
│              application               │
│              (1) │   ▲ (2)             │
│                  ▼   │                 │
│               TUN device               │
│                  │   ▲                 │
│                  ▼   │                 │
│           tmasque  (process)           │
└────────────────────────────────────────┘
               (1) │   ▲ (2)
                   │   │   QUIC / UDP :443
                   ▼   │   HTTP/3 CONNECT-IP · mTLS
            tmasqued (server)

(1) upload   — reads the inner IP packet off the TUN, wraps it in a connect-ip
               context-0 QUIC DATAGRAM, and sends it to the server.
(2) download — unwraps a QUIC DATAGRAM from the server and writes the inner
               IP packet back to the TUN.
```

On connect the client receives its address and routes from the server and installs them
into a dedicated routing table selected by an `fwmark` policy rule — so the tunnel's own
QUIC packets are excluded (no routing loop) while application traffic to the advertised
prefixes is steered into the TUN.

---

## Design notes

- **Inner-TCP congestion control: BBR.** At startup the client sets the *host's* TCP
  congestion control to BBR (`net.ipv4.tcp_congestion_control`), because BBR's rate/RTT
  model tolerates the small non-congestive loss/reorder a userspace tunnel adds (loss-based
  CUBIC would collapse). Inner IP rides unreliable **QUIC DATAGRAMs** (no head-of-line
  blocking, no tunnel-level retransmission); the outer QUIC connection is **CC-off** too
  (post-handshake `SendAny`, pacer-gated), the same as the server — not CUBIC-governed.
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

---

## Forked dependencies (`lib/`, git submodules)

| Submodule | Forked for |
|---|---|
| `quic-go` | CC-off-aware dataplane + datagram-queue fixes shared with the server fork. |
| `connect-ip-go` | IP-packet (context-0) framing for the datagram datapath. |
| `water` | TUN with `IFF_VNET_HDR` support. |

---

## Build & run

```sh
./build.sh                       # outputs build/tmasque
sudo ./build/tmasque             # reads /etc/tmasque/tmasque.conf
```

Requires Linux with TUN support and `NET_ADMIN` (the client uses no raw sockets). The client expects its config
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
