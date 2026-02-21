// Standalone socket option verification for Linux VMs.
// Tests SO_RCVBUF, SO_SNDBUF, SO_REUSEPORT, SO_BUSY_POLL, UDP_GRO, recvmmsg.
// Run: go run ./cmd/sockopt_test/
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	soReusePort = 15
	soBusyPoll  = 46
	udpGRO      = 104
	udpSegment  = 103
)

var (
	passed int
	failed int
)

func check(name string, ok bool, detail string) {
	if ok {
		fmt.Printf("  ✓ %-40s %s\n", name, detail)
		passed++
	} else {
		fmt.Printf("  ✗ %-40s %s\n", name, detail)
		failed++
	}
}

func main() {
	fmt.Printf("=== Socket Option Tests (%s/%s, kernel %s) ===\n\n", runtime.GOOS, runtime.GOARCH, kernelVersion())

	testBufferSizes()
	testReusePort()
	if runtime.GOOS == "linux" {
		testBusyPoll()
		testUDPGRO()
		testRecvmmsg()
	}

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func testBufferSizes() {
	fmt.Println("[SO_RCVBUF / SO_SNDBUF]")
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		check("create socket", false, err.Error())
		return
	}
	defer conn.Close()

	const targetBuf = 4 * 1024 * 1024
	conn.SetReadBuffer(targetBuf)
	conn.SetWriteBuffer(targetBuf)

	raw, _ := conn.SyscallConn()
	var rcvBuf, sndBuf int
	raw.Control(func(fd uintptr) {
		rcvBuf, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		sndBuf, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})

	check("SO_RCVBUF", rcvBuf >= targetBuf, fmt.Sprintf("requested=%d actual=%d", targetBuf, rcvBuf))
	check("SO_SNDBUF", sndBuf >= targetBuf, fmt.Sprintf("requested=%d actual=%d", targetBuf, sndBuf))
}

func testReusePort() {
	fmt.Println("\n[SO_REUSEPORT]")
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			})
			return err
		},
	}

	pc1, err := lc.ListenPacket(nil, "udp", "127.0.0.1:0")
	if err != nil {
		check("first bind", false, err.Error())
		return
	}
	defer pc1.Close()
	addr := pc1.LocalAddr().String()
	check("first bind", true, addr)

	pc2, err := lc.ListenPacket(nil, "udp", addr)
	if err != nil {
		check("second bind (same port)", false, err.Error())
		return
	}
	defer pc2.Close()
	check("second bind (same port)", true, addr)

	pc3, err := lc.ListenPacket(nil, "udp", addr)
	if err != nil {
		check("third bind (same port)", false, err.Error())
		return
	}
	defer pc3.Close()
	check("third bind (same port)", true, addr)
}

func testBusyPoll() {
	fmt.Println("\n[SO_BUSY_POLL]")
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer conn.Close()

	raw, _ := conn.SyscallConn()
	var err error
	raw.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soBusyPoll, 50)
	})
	check("SO_BUSY_POLL=50μs", err == nil, fmt.Sprintf("%v", err))
}

func testUDPGRO() {
	fmt.Println("\n[UDP_GRO / UDP_GSO]")
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer conn.Close()

	raw, _ := conn.SyscallConn()
	var groErr, gsoErr error
	raw.Control(func(fd uintptr) {
		groErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, udpGRO, 1)
		gsoErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, udpSegment, 1400)
	})
	check("UDP_GRO", groErr == nil, fmt.Sprintf("%v", groErr))
	check("UDP_GSO (UDP_SEGMENT=1400)", gsoErr == nil, fmt.Sprintf("%v", gsoErr))
}

func testRecvmmsg() {
	fmt.Println("\n[recvmmsg / sendmmsg via x/net]")

	receiver, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer receiver.Close()
	recvAddr := receiver.LocalAddr().(*net.UDPAddr)

	sender, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sender.Close()

	// Send 32 packets using WriteBatch (sendmmsg)
	senderPC := ipv4.NewPacketConn(sender)
	msgs := make([]ipv4.Message, 32)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{[]byte(fmt.Sprintf("pkt-%02d", i))}
		msgs[i].Addr = recvAddr
	}
	sent, err := senderPC.WriteBatch(msgs, 0)
	check("sendmmsg 32 packets", err == nil && sent == 32, fmt.Sprintf("sent=%d err=%v", sent, err))

	time.Sleep(50 * time.Millisecond)

	// Read using ReadBatch (recvmmsg)
	recvPC := ipv4.NewPacketConn(receiver)
	recvMsgs := make([]ipv4.Message, 64)
	for i := range recvMsgs {
		recvMsgs[i].Buffers = [][]byte{make([]byte, 256)}
	}

	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, err := recvPC.ReadBatch(recvMsgs, 0)
	check("recvmmsg batch", err == nil && n > 0, fmt.Sprintf("received=%d err=%v", n, err))
	check("recvmmsg batch>1 (proves batching)", n > 1, fmt.Sprintf("received=%d", n))
}

func kernelVersion() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "unknown"
	}
	b := make([]byte, 0, 64)
	for _, c := range uname.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
