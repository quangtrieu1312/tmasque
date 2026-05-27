package utility

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// PreReseqTotal / PreReseqOOO measure download-path reorder AS QUIC DELIVERS IT,
// before ForwardReseq runs. They answer: is the ~65% inner-TCP reorder introduced
// by the QUIC transport (wire / receive), or by our reseq stage? If OOO is a large
// fraction of Total, QUIC handed packets to the client out of order (transport
// reorder, which a sender-side fix can't repair); if OOO≈0 but the kernel still
// sees high rcv_ooopack, reseq is the one introducing it.
var (
	PreReseqTotal atomic.Uint64
	PreReseqOOO   atomic.Uint64
)

// PreReseqObserver tracks, per flow, the highest TCP seq seen so far and counts a
// segment as out-of-order on ARRIVAL when its seq is below that high-water mark —
// i.e. a later-sent segment already arrived first. It only measures; it never
// reorders. One observer per tunnel reader, called from that reader's single
// ReadPacket goroutine, so it needs no lock.
type PreReseqObserver struct {
	maxSeq map[flowKey]uint32
}

func NewPreReseqObserver() *PreReseqObserver {
	return &PreReseqObserver{maxSeq: make(map[flowKey]uint32)}
}

// Observe records one received IP packet. Non-TCP / pure ACKs are ignored (same
// filter as reseq). A genuine remote retransmit also registers as out-of-order;
// that's acceptable here because the path is known drop-free, so OOO ≈ reorder.
func (o *PreReseqObserver) Observe(ip []byte) {
	seq, _, key, ok := parseTCP(ip)
	if !ok {
		return
	}
	PreReseqTotal.Add(1)
	mx, seen := o.maxSeq[key]
	switch {
	case !seen:
		// Bound memory on a long run with many short-lived flows.
		if len(o.maxSeq) >= 1<<16 {
			o.maxSeq = make(map[flowKey]uint32)
		}
		o.maxSeq[key] = seq
	case int32(seq-mx) < 0:
		PreReseqOOO.Add(1)
	default:
		o.maxSeq[key] = seq
	}
}

// ForwardReseq restores per-flow ordering on the client's DOWNLOAD receive path,
// right before packets are written to the TUN. QUIC DATAGRAM frames are delivered
// unordered, so even though the server sends a flow's packets in order, reorder
// introduced anywhere in the QUIC transport reaches the inner TCP stream out of
// order and collapses its cwnd. This stage reorders by the inner TCP sequence
// number per flow, so the kernel sees the stream in order.
//
// Because a flow is pinned to one tunnel (server-side flow hash), all of a flow's
// packets arrive on a single tunnel reader, so one ForwardReseq per reader sees
// the whole flow. Unlike the server's variant this one IS accessed from two
// goroutines — the blocking ReadPacket loop (Push) and a ticker (FlushExpired) —
// so it carries a mutex. Non-TCP and pure ACKs pass through immediately. A
// genuinely missing segment is gap-skipped once the per-flow window fills or the
// flow goes idle past maxAge, so a real loss never stalls delivery.
type ForwardReseq struct {
	mu     sync.Mutex
	flows  map[flowKey]*reseqFlow
	window int           // max buffered out-of-order segments per flow before gap-skip
	maxAge time.Duration // a flow idle longer than this is flushed + reaped
}

type flowKey [13]byte // srcIP(4) dstIP(4) srcPort(2) dstPort(2) proto(1)

type reseqEntry struct {
	data      []byte // owned copy of the full IP packet
	nextAfter uint32 // TCP seq immediately following this segment
}

type reseqFlow struct {
	primed   bool
	nextSeq  uint32
	buf      map[uint32]reseqEntry
	lastSeen time.Time
}

// NewForwardReseq creates a resequencer. window bounds how far out of order it
// will hold before giving up on a missing seq; maxAge bounds the latency added
// when a segment is genuinely missing.
func NewForwardReseq(window int, maxAge time.Duration) *ForwardReseq {
	if window <= 0 {
		window = 128
	}
	if maxAge <= 0 {
		maxAge = 5 * time.Millisecond
	}
	return &ForwardReseq{flows: make(map[flowKey]*reseqFlow), window: window, maxAge: maxAge}
}

// Push feeds one received IP packet and appends the packets now ready to deliver,
// in per-flow order, to out. The just-pushed segment references ip directly (write
// it before reusing ip's backing buffer); buffered segments are owned copies, so
// ip may be recycled as soon as Push returns.
func (r *ForwardReseq) Push(ip []byte, now time.Time, out [][]byte) [][]byte {
	seq, nextAfter, key, ok := parseTCP(ip)
	if !ok {
		return append(out, ip)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	f := r.flows[key]
	if f == nil {
		f = &reseqFlow{buf: make(map[uint32]reseqEntry)}
		r.flows[key] = f
	}
	f.lastSeen = now

	if !f.primed {
		f.primed = true
		f.nextSeq = seq
	}

	d := int32(seq - f.nextSeq)
	switch {
	case d == 0:
		out = append(out, ip)
		f.nextSeq = nextAfter
		return r.drain(f, out)
	case d < 0:
		// Retransmit / already-delivered seq: deliver unchanged, don't touch nextSeq.
		return append(out, ip)
	default:
		if _, exists := f.buf[seq]; !exists {
			cp := make([]byte, len(ip))
			copy(cp, ip)
			f.buf[seq] = reseqEntry{data: cp, nextAfter: nextAfter}
		}
		if len(f.buf) > r.window {
			out, _ = r.skipGap(f, out)
		}
		return out
	}
}

// FlushExpired emits buffered segments for flows idle past maxAge (a genuinely
// missing segment must not stall the rest forever) and reaps empty idle flows.
// Call it periodically; safe to call concurrently with Push.
func (r *ForwardReseq) FlushExpired(now time.Time, out [][]byte) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, f := range r.flows {
		if now.Sub(f.lastSeen) < r.maxAge {
			continue
		}
		for len(f.buf) > 0 {
			var ok bool
			out, ok = r.skipGap(f, out)
			if !ok {
				break // only unrecoverable orphans remain — abandon them
			}
		}
		delete(r.flows, k)
	}
	return out
}

// drain emits buffered segments now consecutive with f.nextSeq. Caller holds r.mu.
func (r *ForwardReseq) drain(f *reseqFlow, out [][]byte) [][]byte {
	for {
		e, ok := f.buf[f.nextSeq]
		if !ok {
			return out
		}
		delete(f.buf, f.nextSeq)
		out = append(out, e.data)
		f.nextSeq = e.nextAfter
	}
}

// skipGap abandons the missing f.nextSeq, jumps to the oldest (nearest-future)
// buffered segment, emits it, and drains successors. It sweeps unrecoverable
// past-seq entries so they can't leak or spin the flush loop. Returns false when
// no future segment remains. Caller holds r.mu.
func (r *ForwardReseq) skipGap(f *reseqFlow, out [][]byte) ([][]byte, bool) {
	var oldest uint32
	best := int32(0)
	found := false
	for s := range f.buf {
		dist := int32(s - f.nextSeq)
		if dist <= 0 {
			delete(f.buf, s)
			continue
		}
		if !found || dist < best {
			found, best, oldest = true, dist, s
		}
	}
	if !found {
		return out, false
	}
	e := f.buf[oldest]
	delete(f.buf, oldest)
	out = append(out, e.data)
	f.nextSeq = e.nextAfter
	return r.drain(f, out), true
}

// parseTCP extracts the flow key, TCP sequence, and the following sequence. ok is
// false for anything that should bypass reordering: non-IPv4, non-TCP, truncated
// headers, or zero-advance segments (pure ACKs).
func parseTCP(ip []byte) (seq, nextAfter uint32, key flowKey, ok bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return 0, 0, key, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 { // proto 6 = TCP
		return 0, 0, key, false
	}
	tcp := ip[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return 0, 0, key, false
	}
	seq = binary.BigEndian.Uint32(tcp[4:8])
	payloadLen := len(ip) - ihl - dataOff
	consumed := payloadLen
	flags := tcp[13]
	if flags&0x02 != 0 || flags&0x01 != 0 { // SYN or FIN each consume one seq
		consumed++
	}
	if consumed == 0 {
		return 0, 0, key, false
	}
	copy(key[0:4], ip[12:16])  // src IP
	copy(key[4:8], ip[16:20])  // dst IP
	copy(key[8:10], tcp[0:2])  // src port
	copy(key[10:12], tcp[2:4]) // dst port
	key[12] = 6                // proto
	return seq, seq + uint32(consumed), key, true
}
