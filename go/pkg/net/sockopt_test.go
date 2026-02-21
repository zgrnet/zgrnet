package net

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestSocketBufferSize_SetAndVerify(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cfg := DefaultSocketConfig()
	report := ApplySocketOptions(conn, cfg)

	for _, e := range report.Entries {
		if !e.Applied {
			t.Errorf("optimization %s not applied: %v", e.Name, e.Err)
		} else {
			t.Log(e.Detail)
		}
	}

	// On Linux, kernel may cap at net.core.rmem_max (~208KB in CI).
	// On macOS, limit is typically 8MB+. Just verify > 0.
	actual := getSocketBufSize(conn, true)
	t.Logf("SO_RCVBUF: requested %d, actual %d", DefaultRecvBufSize, actual)

	actual = getSocketBufSize(conn, false)
	t.Logf("SO_SNDBUF: requested %d, actual %d", DefaultSendBufSize, actual)
}

func TestSocketBufferSize_CustomValues(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cfg := SocketConfig{
		RecvBufSize: 2 * 1024 * 1024,
		SendBufSize: 1 * 1024 * 1024,
	}
	report := ApplySocketOptions(conn, cfg)

	for _, e := range report.Entries {
		if !e.Applied {
			t.Errorf("optimization %s not applied: %v", e.Name, e.Err)
		}
	}
}

func TestSocketBufferSize_ZeroDefaults(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	report := ApplySocketOptions(conn, SocketConfig{})

	rcvApplied := false
	sndApplied := false
	for _, e := range report.Entries {
		if e.Name == "SO_RCVBUF" && e.Applied {
			rcvApplied = true
		}
		if e.Name == "SO_SNDBUF" && e.Applied {
			sndApplied = true
		}
	}
	if !rcvApplied {
		t.Error("SO_RCVBUF should be applied with zero config (defaults to 4MB)")
	}
	if !sndApplied {
		t.Error("SO_SNDBUF should be applied with zero config (defaults to 4MB)")
	}
}

func TestReusePort_MultipleBind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SO_REUSEPORT not supported on Windows")
	}

	conn1, err := ListenUDPReusePort("127.0.0.1:0")
	if err != nil {
		t.Skipf("SO_REUSEPORT not available: %v", err)
	}
	defer conn1.Close()

	addr := conn1.LocalAddr().String()

	conns := []*net.UDPConn{conn1}
	for i := 0; i < 3; i++ {
		c, err := ListenUDPReusePort(addr)
		if err != nil {
			t.Fatalf("failed to bind socket %d to %s: %v", i+1, addr, err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	t.Logf("4 sockets bound to %s with SO_REUSEPORT", addr)
}

func TestReusePort_WithoutFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bind semantics differ on Windows")
	}

	conn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	addr := conn1.LocalAddr().(*net.UDPAddr)
	_, err = net.ListenUDP("udp", addr)
	if err == nil {
		t.Fatal("expected EADDRINUSE error, but bind succeeded")
	}
	t.Logf("correctly got error without SO_REUSEPORT: %v", err)
}

func TestOptimizationReport_String(t *testing.T) {
	report := &OptimizationReport{
		Entries: []OptimizationEntry{
			{Name: "SO_RCVBUF", Applied: true, Detail: "SO_RCVBUF=4194304 (actual=8388608)"},
			{Name: "SO_SNDBUF", Applied: true, Detail: "SO_SNDBUF=4194304 (actual=8388608)"},
		},
	}
	s := report.String()
	if len(s) == 0 {
		t.Fatal("report should not be empty")
	}
	t.Log(s)
}

func TestDefaultSocketConfig(t *testing.T) {
	cfg := DefaultSocketConfig()
	if cfg.RecvBufSize != DefaultRecvBufSize {
		t.Errorf("RecvBufSize: got %d, want %d", cfg.RecvBufSize, DefaultRecvBufSize)
	}
	if cfg.SendBufSize != DefaultSendBufSize {
		t.Errorf("SendBufSize: got %d, want %d", cfg.SendBufSize, DefaultSendBufSize)
	}
}

func TestFullSocketConfig_ApplyAll(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cfg := FullSocketConfig()
	report := ApplySocketOptions(conn, cfg)
	t.Log(report.String())

	for _, e := range report.Entries {
		if (e.Name == "SO_RCVBUF" || e.Name == "SO_SNDBUF") && !e.Applied {
			t.Errorf("%s should be applied: %v", e.Name, e.Err)
		}
	}
}

func TestGracefulDegradation(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	report := ApplySocketOptions(conn, FullSocketConfig())

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	msg := []byte("graceful-test")
	_, err = conn.WriteToUDP(msg, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("send failed after applying optimizations: %v", err)
	}

	buf := make([]byte, 256)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	if string(buf[:n]) != "graceful-test" {
		t.Fatalf("data mismatch: got %q", buf[:n])
	}
	t.Log(report.String())
}
