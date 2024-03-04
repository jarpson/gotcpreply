package tcpreader

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type tcpFlag int

const (
	tcpFlagNone tcpFlag = iota
	tcpFlagSYN
	tcpFlagFIN
	tcpFlagRST
	tcpFlagPSH
	tcpFlagACK
)

func makeTCPLayers(data tcpData) *layers.TCP {
	ret := &layers.TCP{
		Seq: data.Seq,
		BaseLayer: layers.BaseLayer{
			Payload: []byte(data.Data),
		},
	}

	switch data.Flag {
	case tcpFlagSYN:
		ret.SYN = true
	case tcpFlagFIN:
		ret.FIN = true
	case tcpFlagRST:
		ret.RST = true
	case tcpFlagPSH:
		ret.PSH = true
	case tcpFlagACK:
		ret.ACK = true
	default:
	}

	return ret
}

type tcpData struct {
	Seq  uint32
	Data string
	Flag tcpFlag
	TS   int64 // unix time
}

type tcpWant struct {
	Seq        sequence // next seq
	ChLen      int      // chan len
	BufLen     int      // buffer len
	WaitHeader bool     // wait header
	Closed     bool     // is closed
}

func (t *tcpWant) Compair(stream *tcpStream) error {
	switch {
	case t.Seq != stream.nextSeq:
		return fmt.Errorf("seq not equal want %d got %d", t.Seq, stream.nextSeq)
	case t.ChLen != len(stream.recvCh):
		return fmt.Errorf("ch len not equal want %d got %d", t.ChLen, len(stream.recvCh))
	case t.BufLen != stream.assembler.Len():
		return fmt.Errorf("cache len not equal want %d got %d", t.BufLen, stream.assembler.Len())
	case t.WaitHeader != stream.waitHeader:
		return fmt.Errorf("waitHeader not equal want %v got %v", t.WaitHeader, stream.waitHeader)
	case t.Closed != stream.closed:
		return fmt.Errorf("closed not equal want %v got %v", t.Closed, stream.closed)
	}
	return nil
}

type testSequence struct {
	Req  tcpData
	Want tcpWant
	Msg  string
}

var (
	netFlow, _ = gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}))
)

type testStreamFactory struct {
	flow         string
	stream       *tcpStream
	streamNewNum int
}

func (t *testStreamFactory) New(flow string, stream Stream) {
	t.streamNewNum++
	t.flow = flow
	t.stream = stream.(*tcpStream)
}

func TestTCPStreamNormal(t *testing.T) {
	specs := []testSequence{
		{
			tcpData{9, "", tcpFlagSYN, 1000},
			tcpWant{10, 0, 0, false, false},
			"syn message start stream",
		},
		{
			tcpData{10, "", tcpFlagACK, 1000},
			tcpWant{10, 0, 0, false, false},
			"ingor empty data",
		},
		{
			tcpData{10, "abcde", tcpFlagPSH, 1000},
			tcpWant{15, 1, 0, false, false},
			"normal data",
		},
		{
			tcpData{10, "abcde", tcpFlagPSH, 1000},
			tcpWant{15, 1, 0, false, false},
			"old data drop",
		},
		{
			tcpData{11, "bcdef", tcpFlagPSH, 1000},
			tcpWant{16, 2, 0, false, false},
			"old data keep",
		},
		{
			tcpData{18, "ij", tcpFlagPSH, 1000},
			tcpWant{16, 2, 1, false, false},
			"new data cache",
		},
		{
			tcpData{18, "ijk", tcpFlagPSH, 1000},
			tcpWant{16, 2, 1, false, false},
			"new data cache ingor",
		},
		{
			tcpData{19, "jkl", tcpFlagPSH, 1000},
			tcpWant{16, 2, 2, false, false},
			"new data cache keep",
		},
		{
			tcpData{16, "gh", tcpFlagPSH, 1000},
			tcpWant{22, 5, 0, false, false},
			"normal data before cache cache",
		},
		{
			tcpData{22, "", tcpFlagFIN, 1000},
			tcpWant{22, 5, 0, false, true},
			"normal data before cache cache",
		},
	}

	chSpec := []string{"abcde", "f", "gh", "ijk", "l"}

	factory := &testStreamFactory{}
	pool := NewStreamPool(factory, StreamConfig{
		MaxBuffered: 3,
	})

	t.Log("test sync")

	for idx, spec := range specs {
		tcp := makeTCPLayers(spec.Req)
		pool.AssembleWithTimestamp(netFlow, tcp, time.Unix(spec.Req.TS, 0))
		if err := spec.Want.Compair(factory.stream); err != nil {
			t.Fatalf("test-%d '%s' fail:%v", idx, spec.Msg, err)
		}
	}

	// get data
	ch := factory.stream.Recv()
	for idx, spec := range chSpec {
		if err := chRead(ch, spec, true, false); err != nil {
			t.Fatalf("test chSpec-%d fail: %v", idx, err)
		}
	}

	if err := chRead(ch, "", false, false); err != nil {
		t.Fatalf("test chSpec-final fail: %v", err)
	}

	if factory.streamNewNum != 1 {
		t.Fatalf("test stream new should be 1,bug got %d", factory.streamNewNum)
	}
}

func TestTCPStreamOverFlow(t *testing.T) {
	// 10 12 14 16 18 20 22 24 26
	// ab cd ef gh ij kl mn op qr
	// ab cd ij op mn ef qr
	specs := []testSequence{
		{
			tcpData{10, "ab", tcpFlagPSH, 1000},
			tcpWant{12, 2, 0, false, false},
			"normal data1 without syn",
		},
		{
			tcpData{12, "cd", tcpFlagPSH, 1000},
			tcpWant{14, 3, 0, false, false},
			"normal data2",
		},
		{
			tcpData{18, "ij", tcpFlagPSH, 1000},
			tcpWant{14, 3, 1, false, false},
			"new data1",
		},
		{
			tcpData{24, "op", tcpFlagPSH, 1000},
			tcpWant{14, 3, 2, false, false},
			"new data2",
		},
		{
			tcpData{22, "mn", tcpFlagPSH, 1000},
			tcpWant{14, 3, 3, false, false},
			"new data3",
		},
		{
			tcpData{14, "ef", tcpFlagPSH, 1000},
			tcpWant{16, 2, 3, false, false},
			"ch overflow",
		},
		{
			tcpData{26, "qr", tcpFlagPSH, 1000},
			tcpWant{26, 3, 0, false, false},
			"cache overflow",
		},
	}

	chSpec := []string{"", "mn", "op"}

	oldBufferMin := recvBufferMin
	recvBufferMin = 3
	defer func() {
		recvBufferMin = oldBufferMin
	}()
	factory := &testStreamFactory{}
	pool := NewStreamPool(factory, StreamConfig{
		RecvBufferLen: 3,
		MaxBuffered:   3,
	})

	t.Log("test sync")

	for idx, spec := range specs {
		tcp := makeTCPLayers(spec.Req)
		pool.AssembleWithTimestamp(netFlow, tcp, time.Unix(spec.Req.TS, 0))
		if err := spec.Want.Compair(factory.stream); err != nil {
			t.Fatalf("test-%d '%s' fail:%v", idx, spec.Msg, err)
		}
	}

	// get data
	ch := factory.stream.Recv()
	for idx, spec := range chSpec {
		if err := chRead(ch, spec, true, false); err != nil {
			t.Fatalf("test chSpec-%d fail: %v", idx, err)
		}
	}

	if err := chRead(ch, "", false, true); err != nil {
		t.Fatalf("test chSpec-final fail: %v", err)
	}

	// not expire
	pool.FlushOlderThan(time.Unix(100, 0))
	if err := chRead(ch, "", false, true); err != nil {
		t.Fatalf("test chSpec-final fail: %v", err)
	}

	// expire
	pool.FlushOlderThan(time.Unix(1001, 0))
	if err := chRead(ch, "", false, false); err != nil {
		t.Fatalf("test chSpec-final fail: %v", err)
	}
	if factory.stream.Closed() != true {
		t.Fatalf("test stream shoud closed ")
	}

	factory.stream.Close()

	if factory.streamNewNum != 1 {
		t.Fatalf("test stream new should be 1,bug got %d", factory.streamNewNum)
	}
}

func chRead(ch <-chan []byte, wantBuf string, wantOK, wantBlocked bool) error {
	select {
	case buf, ok := <-ch:
		if ok != wantOK {
			return fmt.Errorf("readCh stats want %v got %v", wantOK, ok)
		}
		if ok && string(buf) != string(wantBuf) {
			return fmt.Errorf("readCh buf want '%s', got '%s'", wantBuf, buf)
		}
	default:
		if !wantBlocked {
			return fmt.Errorf("readCh except unblocked")
		}
	}

	return nil
}
