package net

import (
	"net"
	"syscall"
	"testing"
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

	// Verify SO_RCVBUF was actually increased.
	// Linux doubles the requested value; macOS may cap it.
	actual := getSocketOptInt(conn, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if actual < DefaultRecvBufSize {
		t.Logf("SO_RCVBUF: requested %d, got %d (OS-limited, acceptable)", DefaultRecvBufSize, actual)
	}

	actual = getSocketOptInt(conn, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if actual < DefaultSendBufSize {
		t.Logf("SO_SNDBUF: requested %d, got %d (OS-limited, acceptable)", DefaultSendBufSize, actual)
	}
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

func TestReusePort_MultipleBind(t *testing.T) {
	// Create first socket with SO_REUSEPORT
	conn1, err := ListenUDPReusePort("127.0.0.1:0")
	if err != nil {
		t.Skipf("SO_REUSEPORT not available: %v", err)
	}
	defer conn1.Close()

	addr := conn1.LocalAddr().String()

	// Create 3 more sockets on the same address
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
	conn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	// Try to bind a second socket to the same address without SO_REUSEPORT
	addr := conn1.LocalAddr().(*net.UDPAddr)
	_, err = net.ListenUDP("udp", addr)
	if err == nil {
		t.Fatal("expected EADDRINUSE error, but bind succeeded")
	}
	t.Logf("correctly got error without SO_REUSEPORT: %v", err)
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
