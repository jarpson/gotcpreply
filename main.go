package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jarpson/gotcpreply/tcpreader"
)

const (
	levelDebug int = iota
	levelInfo
	levelWarn
	levelError
)

const (
	defaultRedisRegexp   = `^\*\d+\r\n\$`
	defaultRedisClietOff = "*3\r\n$6\r\nclient\r\n$5\r\nreply\r\n$3\r\noff\r\n"
)

var (
	snapshotLen = int32(1024)
	promiscuous = false

	recvChLen   = 1024
	tcpCacheMax = 3
	tcpTimeout  = time.Minute

	tcpDailTimeout  = time.Second
	tcpWriteTimeout = time.Second
	checkHeader     = func([]byte) bool {
		return true
	}

	logLevel           int
	forwardingTarget   string
	sendPerConnMessage []byte
)

// ForwardStreamFactory implements tcpassembly.ForwardStreamFactory
type ForwardStreamFactory struct {
}

// New creates a new Stream from a TCP assembler
func (s *ForwardStreamFactory) New(flow string, tcp tcpreader.Stream) {
	stream := &ForwardStream{
		flow:   flow,
		stream: tcp,
	}

	go stream.run()
}

// ForwardStream handles forwarding data for a single TCP stream
type ForwardStream struct {
	flow   string
	stream tcpreader.Stream
	conn   net.Conn
	skip   bool
}

func (s *ForwardStream) run() {
	defer func() {
		s.closeForwareConn(nil)

		if logLevel <= levelInfo {
			log.Printf("[Info] pcap stream closed %s", s.String())
		}
	}()

	if logLevel <= levelInfo {
		log.Printf("[Info] pcap stream created %s", s.String())
	}

	ch := s.stream.Recv()

	for !s.stream.Closed() {
		buf, ok := <-ch
		if !ok {
			// stream closed
			return
		}

		s.Write(buf)
	}
}

func (s *ForwardStream) String() string {
	return fmt.Sprintf("stream(%s forward_to %s)",
		s.flow, forwardingTarget)
}

// forwardData forwards TCP layer data to the target service
func (s *ForwardStream) Write(buffer []byte) {
	if logLevel <= levelDebug {
		fmt.Printf("%s", buffer)
		if forwardingTarget == "" {
			return
		}
	}

	if len(buffer) == 0 {
		s.closeForwareConn(fmt.Errorf("pcap write full"))
		return
	}

	conn := s.getOrCreateForwareConn()
	if conn == nil {
		s.skip = true
		return
	}

	if s.skip && !checkHeader(buffer) {
		if logLevel <= levelDebug {
			log.Printf("[Debug] Skip Write len(%d) %s", len(buffer), s.String())
		}
		return
	}

	conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))

	nw, err := conn.Write(buffer)
	if err != nil {
		s.closeForwareConn(err)
		return
	}

	if nw < len(buffer) {
		s.closeForwareConn(fmt.Errorf("Error write skip %d<%d", nw, len(buffer)))
		return
	}

	return
}

func (s *ForwardStream) closeForwareConn(err error) {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
		s.skip = true
		if err != nil && logLevel <= levelError {
			log.Printf("[Error] Closed forward %s, err %v", s.String(), err)
		} else if logLevel <= levelInfo {
			log.Printf("[Info] Closed forward %s, err %v", s.String(), err)
		}
	}
}

// createForwareConn create connection to forward target, background read and discard
func (s *ForwardStream) getOrCreateForwareConn() net.Conn {
	if s.conn != nil {
		return s.conn
	}

	conn, err := net.DialTimeout("tcp", forwardingTarget, tcpDailTimeout)

	if err != nil && logLevel <= levelError {
		log.Printf("[Error] Create fowrard %s, err:%v", s.String(), err)
	} else if logLevel <= levelInfo {
		log.Printf("[Info] create fowrard %s, err:%v", s.String(), err)
	}

	if err != nil {
		return nil
	}
	s.conn = conn
	if len(sendPerConnMessage) > 0 {
		conn.Write(sendPerConnMessage)
	}

	go func() {
		for {
			_, err := io.Copy(io.Discard, conn)
			if err != nil {
				return
			}
		}
	}()

	return conn
}

func main() {
	pDev := flag.String("device", "lo0", "net device")
	filter := flag.String("filter", "tcp dst port 6379", "cap filter")
	flag.StringVar(&forwardingTarget, "target", "", "transfer target address")
	plevel := flag.String("level", "info", "log level, use: debug info warn error")
	pclientoff := flag.String("sendmsg", defaultRedisClietOff, "sed the message to each target conn")
	pHeader := flag.String("header", defaultRedisRegexp, "filter header regexp")

	flag.Parse()

	switch *plevel {
	case "debug":
		logLevel = levelDebug
	case "info":
		logLevel = levelInfo
	case "warn":
		logLevel = levelWarn
	case "error":
		logLevel = levelError
	default:
		fmt.Println("Usage: 'level' must in (debug,info,warn,error)")
		os.Exit(1)
	}

	if *pDev == "" || *filter == "" {
		fmt.Println("Usage: 'device' or 'filter' or 'target' cannot empty")
		os.Exit(1)
	}

	if forwardingTarget == "" {
		log.Println("target address empty, will not transfer, only print data")
	} else {
		log.Printf("cap(%s), transfer to (%s)\n", *filter, forwardingTarget)
	}

	handle, err := pcap.OpenLive(*pDev, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	if err := handle.SetBPFFilter(*filter); err != nil { // optional
		panic(err)
	}

	if *pHeader != "" {
		log.Printf("Package Header Filter (%s)", *pHeader)
		re := regexp.MustCompile(*pHeader)

		checkHeader = func(buf []byte) bool {
			return re.Match(buf)
		}
	}

	sendPerConnMessage = []byte(*pclientoff)

	// Create TCP assembler
	streamFactory := &ForwardStreamFactory{}
	streamPool := tcpreader.NewStreamPool(streamFactory, tcpreader.StreamConfig{
		RecvBufferLen: recvChLen,
		MaxBuffered:   tcpCacheMax,
	})

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Second * 30)

	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil {
				continue
			}

			transportLayer := packet.TransportLayer()
			if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
				tcp := transportLayer.(*layers.TCP)
				streamPool.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		case <-ticker:
			// flush not active connecion
			streamPool.FlushOlderThan(time.Now().Add(-tcpTimeout))
		}
	}
}
