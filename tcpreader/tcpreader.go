package tcpreader

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var nilBytes = []byte{}

var (
	recvBufferMin = 128
)

// Stream stream for watcher
type Stream interface {
	// Closed check stream closed
	Closed() bool
	// Recv data from stream;
	// chan closed when Stream close;
	// return empty bytes when stream lost some data.
	Recv() <-chan []byte
}

// StreamFactory is used by assembly to create a new stream for each
// new TCP session.
type StreamFactory interface {
	// Notify new stream created
	New(flow string, stream Stream)
}

func flowToKey(netFlow gopacket.Flow, sport, dport layers.TCPPort) string {
	return fmt.Sprintf("%s:%d->%s:%d",
		netFlow.Src().String(), sport,
		netFlow.Dst().String(), dport)
}

// StreamConfig config of tcp stream
type StreamConfig struct {
	// RecvBufferLen recv channel length,
	// min is recvBufferMin(128)
	RecvBufferLen int
	// MaxBuffered is an upper limit on the number of
	// out-of-order packet.
	MaxBuffered int
}

// StreamPool storage all cap tcp stream
// Notice: cannot run at muti threads
type StreamPool struct {
	cfg     StreamConfig
	factory StreamFactory
	pool    map[string]*tcpStream
}

// NewStreamPool new tcp stream reassembly pool
func NewStreamPool(factory StreamFactory, cfg StreamConfig) *StreamPool {
	return &StreamPool{
		cfg:     cfg,
		factory: factory,
		pool:    make(map[string]*tcpStream),
	}
}

func (p *StreamPool) getStream(key string) *tcpStream {
	s := p.pool[key]
	if s != nil {
		return s
	}

	s = newTCPStream(&p.cfg)
	p.pool[key] = s
	p.factory.New(key, s)

	return s
}

func (p *StreamPool) closeStream(key string) {
	if s := p.pool[key]; s != nil {
		delete(p.pool, key)
		s.Close()
	}
}

// AssembleWithTimestamp write tcp package from pcap
func (p *StreamPool) AssembleWithTimestamp(netFlow gopacket.Flow, t *layers.TCP, timestamp time.Time) { // Ignore empty TCP packets
	payload := t.LayerPayload()
	if len(payload) == 0 {
		if t.SYN {
			conn := p.getStream(flowToKey(netFlow, t.SrcPort, t.DstPort))
			conn.WriteSYN(t.Seq)
		} else if t.FIN || t.RST {
			p.closeStream(flowToKey(netFlow, t.SrcPort, t.DstPort))
		}
		return
	}

	conn := p.getStream(flowToKey(netFlow, t.SrcPort, t.DstPort))
	conn.Write(t, timestamp)
}

// FlushOlderThan close connection last input data time < `t`
func (p *StreamPool) FlushOlderThan(t time.Time) {
	needClosed := make([]string, 0, 10)
	for key, s := range p.pool {
		if s.Before(t) {
			s.Close()
			needClosed = append(needClosed, key)
		}
	}
	// delete stream
	for _, key := range needClosed {
		delete(p.pool, key)
	}
}

// tcpStream a tcp stream
type tcpStream struct {
	cfg        *StreamConfig
	waitHeader bool
	recvCh     chan []byte
	assembler  assemblerCache
	nextSeq    sequence
	lastSeen   time.Time
	closed     bool
}

// newTCPStream create new tcp stream
func newTCPStream(cfg *StreamConfig) *tcpStream {
	return &tcpStream{
		cfg:        cfg,
		waitHeader: true,
		recvCh:     make(chan []byte, max(cfg.RecvBufferLen, recvBufferMin)),
		assembler:  newAssemblerCache(cfg.MaxBuffered),
	}
}

// WriteSYN write syn package
func (t *tcpStream) WriteSYN(seq uint32) {
	if t.waitHeader {
		t.nextSeq = sequence(seq).Add(1)
		t.waitHeader = false
	}
}

// Write write data to tcp stream
func (t *tcpStream) Write(tcp *layers.TCP, timestamp time.Time) {
	if t.lastSeen.Before(timestamp) {
		t.lastSeen = timestamp
	}

	t.doWrite(tcp, true)
}

func (t *tcpStream) doWrite(tcp *layers.TCP, withBuffer bool) bool {
	s := sequence(tcp.Seq)
	buf := tcp.LayerPayload()
	e := s.Add(len(buf))
	if t.waitHeader {
	} else if t.nextSeq == s {
		// received next package
	} else if t.nextSeq.Less(s) {
		// t.nextSeq < s: some package lost
		if withBuffer {
			t.addToBuffer(tcp)
		}
		return false
	} else if t.nextSeq.Less(e) {
		//  s < t.nextSeq < e
		buf = buf[t.nextSeq.Sub(s):]
	} else {
		// ignor prev pkg
		return true
	}

	t.sendToChannel(e, buf)
	t.trySendBuffere()
	return true
}

func (t *tcpStream) trySendBuffere() {
	for e := t.assembler.Front(); e != nil; {
		next := e.Next()
		val := e.Value.(*layers.TCP)
		if !t.doWrite(val, false) {
			return
		}
		t.assembler.Remove(e)
		e = next
	}
}

func (t *tcpStream) addToBuffer(tcp *layers.TCP) {
	if t.assembler.InsertOrderd(tcp) {
		// add to buffer success
		return
	}

	// tcp buffer full, will lost package
	t.waitHeader = true

	if t.assembler.TrimDiscontinuous() {
		t.trySendBuffere()
	}
}

func (t *tcpStream) clearChannel() {
	for {
		select {
		case <-t.recvCh:
		default:
			return
		}
	}
}

func (t *tcpStream) sendToChannel(end sequence, buf []byte) {
	if t.waitHeader {
		t.clearChannel()
		t.recvCh <- nilBytes
		t.waitHeader = false
	}

	t.nextSeq = end

	select {
	case t.recvCh <- buf:
		return
	default:
	}

	// recv buffer full, clear it and re put
	t.waitHeader = true
	// will clear channel and re put,
	// because channel cap greater than 128, so it must success
	t.sendToChannel(end, buf)
}

// Before check stream last write time before `timestamp`
func (t *tcpStream) Before(timestamp time.Time) bool {
	return t.lastSeen.Before(timestamp)
}

// Close close tcp stream
func (t *tcpStream) Close() {
	if t.closed {
		return
	}

	t.closed = true
	close(t.recvCh)
}

// Closed check this stream is closed
func (t *tcpStream) Closed() bool {
	return t.closed
}

// Recv data from stream
func (t *tcpStream) Recv() <-chan []byte {
	return t.recvCh
}
