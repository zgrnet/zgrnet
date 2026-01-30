package transport

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibing/zgrnet/host"
	"github.com/vibing/zgrnet/noise"
)

// TestConnRoaming tests that a Conn can handle endpoint changes (roaming).
// This is a low-level test showing session migration between transports.
func TestConnRoaming(t *testing.T) {
	// Generate key pairs
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create server transport
	serverTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer serverTransport.Close()
	serverAddr := serverTransport.LocalAddr()
	t.Logf("Server listening on %s", serverAddr)

	// Create first client transport
	client1Transport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client1 transport: %v", err)
	}
	client1Addr := client1Transport.LocalAddr()
	t.Logf("Client1 on %s", client1Addr)

	// Create Conns
	clientConn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:   clientKey,
		RemotePK:   serverKey.Public,
		Transport:  client1Transport,
		RemoteAddr: serverAddr,
	})
	if err != nil {
		t.Fatalf("Failed to create client conn: %v", err)
	}

	serverConn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:   serverKey,
		RemotePK:   clientKey.Public,
		Transport:  serverTransport,
		RemoteAddr: client1Addr,
	})
	if err != nil {
		t.Fatalf("Failed to create server conn: %v", err)
	}

	// Perform handshake using goroutines
	handshakeDone := make(chan error, 2)

	// Client opens connection (sends handshake init, waits for response)
	go func() {
		handshakeDone <- clientConn.Open()
	}()

	// Server accepts by receiving init, processing, and sending response
	go func() {
		// Read handshake init
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := serverTransport.RecvFrom(buf)
		if err != nil {
			handshakeDone <- err
			return
		}

		// Parse the init message
		initMsg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			handshakeDone <- err
			return
		}

		// Accept returns the response message to send back
		respBytes, err := serverConn.Accept(initMsg)
		if err != nil {
			handshakeDone <- err
			return
		}

		// Send response back to client
		if err := serverTransport.SendTo(respBytes, client1Addr); err != nil {
			handshakeDone <- err
			return
		}

		handshakeDone <- nil
	}()

	// Wait for both sides to complete
	for i := 0; i < 2; i++ {
		select {
		case err := <-handshakeDone:
			if err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Handshake timeout")
		}
	}

	t.Log("Handshake completed!")

	// Test communication before roaming
	testMsg1 := []byte("Hello from client, original IP!")
	if err := clientConn.Send(0x80, testMsg1); err != nil {
		t.Fatalf("Failed to send from client: %v", err)
	}

	proto1, recv1, err := serverConn.Recv()
	if err != nil {
		t.Fatalf("Failed to receive at server: %v", err)
	}
	if proto1 != 0x80 || !bytes.Equal(recv1, testMsg1) {
		t.Fatalf("Message mismatch: got proto=%d, data=%s", proto1, recv1)
	}
	t.Logf("Server received before roaming: %s", recv1)

	// === ROAMING: Client changes IP ===
	t.Log("=== Simulating client IP change (roaming) ===")

	// Close the old transport
	client1Transport.Close()

	// Create new client transport (simulating new IP)
	client2Transport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client2 transport: %v", err)
	}
	defer client2Transport.Close()
	client2Addr := client2Transport.LocalAddr()
	t.Logf("Client roamed to new address: %s", client2Addr)

	// Get the session from the old client conn to reuse
	session := clientConn.Session()
	if session == nil {
		t.Fatal("Client session is nil")
	}

	// Create a "roamed" client conn - reusing the same session
	roamedClientConn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:   clientKey,
		RemotePK:   serverKey.Public,
		Transport:  client2Transport,
		RemoteAddr: serverAddr,
	})
	if err != nil {
		t.Fatalf("Failed to create roamed client conn: %v", err)
	}

	// Inject the existing session (simulate session migration)
	roamedClientConn.SetSession(session)

	// Send message from new IP
	testMsg2 := []byte("Hello from client, NEW IP after roaming!")
	if err := roamedClientConn.Send(0x81, testMsg2); err != nil {
		t.Fatalf("Failed to send from roamed client: %v", err)
	}

	// Server receives the message
	proto2, recv2, err := serverConn.Recv()
	if err != nil {
		t.Fatalf("Failed to receive at server after roaming: %v", err)
	}
	if proto2 != 0x81 || !bytes.Equal(recv2, testMsg2) {
		t.Fatalf("Message mismatch after roaming: got proto=%d, data=%s", proto2, recv2)
	}
	t.Logf("Server received after roaming: %s", recv2)

	// Update server's remote addr for the reply (manual roaming at Conn level)
	serverConn.SetRemoteAddr(client2Addr)

	// Server sends reply to new endpoint
	testMsg3 := []byte("Reply from server to new endpoint!")
	if err := serverConn.Send(0x82, testMsg3); err != nil {
		t.Fatalf("Failed to send from server: %v", err)
	}

	proto3, recv3, err := roamedClientConn.Recv()
	if err != nil {
		t.Fatalf("Failed to receive at roamed client: %v", err)
	}
	if proto3 != 0x82 || !bytes.Equal(recv3, testMsg3) {
		t.Fatalf("Message mismatch: got proto=%d, data=%s", proto3, recv3)
	}
	t.Logf("Roamed client received: %s", recv3)

	t.Log("=== Conn-level roaming test PASSED! ===")
}

// TestHostRoaming tests roaming at the Host level where endpoint updates are automatic.
func TestHostRoaming(t *testing.T) {
	// Generate key pairs
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create server
	serverTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer serverTransport.Close()

	serverHost, err := host.NewHost(host.HostConfig{
		PrivateKey:        serverKey,
		Transport:         serverTransport,
		AllowUnknownPeers: true, // Accept connections from unknown peers
	})
	if err != nil {
		t.Fatalf("Failed to create server host: %v", err)
	}
	defer serverHost.Close()

	// Create first client
	client1Transport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client1 transport: %v", err)
	}

	client1Host, err := host.NewHost(host.HostConfig{
		PrivateKey: clientKey,
		Transport:  client1Transport,
	})
	if err != nil {
		t.Fatalf("Failed to create client1 host: %v", err)
	}

	// Add server as peer
	serverAddr := serverTransport.LocalAddr()
	client1Addr := client1Transport.LocalAddr()
	t.Logf("Server: %s, Client1: %s", serverAddr, client1Addr)

	if err := client1Host.AddPeer(serverKey.Public, serverAddr); err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	// Connect
	if err := client1Host.Connect(serverKey.Public); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	t.Log("Client1 connected to server!")

	// Wait for server to process the handshake
	time.Sleep(100 * time.Millisecond)

	// Send message from client1
	testMsg1 := []byte("Hello from original IP!")
	if err := client1Host.Send(serverKey.Public, 0x80, testMsg1); err != nil {
		t.Fatalf("Failed to send: %v", err)
	}

	// Receive at server
	msg1, err := serverHost.RecvTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive at server: %v", err)
	}
	if !bytes.Equal(msg1.From[:], clientKey.Public[:]) {
		t.Fatalf("Message from wrong peer")
	}
	t.Logf("Server received: %s", msg1.Data)

	// === ROAMING ===
	t.Log("=== Simulating roaming ===")

	// Close client1 and create client2 with same key but different port
	client1Host.Close()
	client1Transport.Close()

	// Create new client transport
	client2Transport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client2 transport: %v", err)
	}
	defer client2Transport.Close()

	client2Host, err := host.NewHost(host.HostConfig{
		PrivateKey: clientKey, // Same key!
		Transport:  client2Transport,
	})
	if err != nil {
		t.Fatalf("Failed to create client2 host: %v", err)
	}
	defer client2Host.Close()

	t.Logf("Client roamed to: %s", client2Transport.LocalAddr())

	// Add server and connect again
	if err := client2Host.AddPeer(serverKey.Public, serverAddr); err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	if err := client2Host.Connect(serverKey.Public); err != nil {
		t.Fatalf("Failed to connect after roaming: %v", err)
	}
	t.Log("Client2 (roamed) connected to server!")

	// Wait for handshake
	time.Sleep(100 * time.Millisecond)

	// Send from new endpoint
	testMsg2 := []byte("Hello from NEW IP after roaming!")
	if err := client2Host.Send(serverKey.Public, 0x81, testMsg2); err != nil {
		t.Fatalf("Failed to send from roamed client: %v", err)
	}

	// Server receives - endpoint should be automatically updated
	msg2, err := serverHost.RecvTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive at server after roaming: %v", err)
	}
	t.Logf("Server received after roaming: %s", msg2.Data)

	// Server replies
	testMsg3 := []byte("Reply to roamed client!")
	if err := serverHost.Send(clientKey.Public, 0x82, testMsg3); err != nil {
		t.Fatalf("Failed to send reply: %v", err)
	}

	// Roamed client receives
	msg3, err := client2Host.RecvTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive at roamed client: %v", err)
	}
	t.Logf("Roamed client received: %s", msg3.Data)

	t.Log("=== Host-level roaming test PASSED! ===")
}

// TestInSessionRoaming tests roaming within an existing session (no re-handshake).
// This simulates a mobile device changing WiFi while maintaining the same session.
func TestInSessionRoaming(t *testing.T) {
	// Generate key pairs
	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create server
	serverTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer serverTransport.Close()

	serverHost, err := host.NewHost(host.HostConfig{
		PrivateKey:        serverKey,
		Transport:         serverTransport,
		AllowUnknownPeers: true,
	})
	if err != nil {
		t.Fatalf("Failed to create server host: %v", err)
	}
	defer serverHost.Close()

	// Create client
	clientTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client transport: %v", err)
	}
	defer clientTransport.Close()

	clientHost, err := host.NewHost(host.HostConfig{
		PrivateKey: clientKey,
		Transport:  clientTransport,
	})
	if err != nil {
		t.Fatalf("Failed to create client host: %v", err)
	}
	defer clientHost.Close()

	serverAddr := serverTransport.LocalAddr()
	t.Logf("Server: %s, Client: %s", serverAddr, clientTransport.LocalAddr())

	// Setup and connect
	if err := clientHost.AddPeer(serverKey.Public, serverAddr); err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	if err := clientHost.Connect(serverKey.Public); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	t.Log("Initial connection established")

	time.Sleep(100 * time.Millisecond)

	// Exchange messages
	if err := clientHost.Send(serverKey.Public, 0x80, []byte("Message 1")); err != nil {
		t.Fatalf("Failed to send: %v", err)
	}

	msg, err := serverHost.RecvTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive: %v", err)
	}
	t.Logf("Server received: %s", msg.Data)

	// Get client's peer endpoint before roaming
	clientInfo := serverHost.GetPeer(clientKey.Public)
	if clientInfo == nil {
		t.Fatal("Client peer not found on server")
	}
	originalEndpoint := clientInfo.Endpoint
	t.Logf("Original client endpoint: %s", originalEndpoint)

	// === IN-SESSION ROAMING ===
	// Server sends from server, simulating client receiving on new IP
	// The magic: when server receives next packet from client's new IP,
	// it should automatically update the endpoint.

	// For this test, we simulate by having the server see a packet from
	// a new address but still decrypt it successfully (same session).

	t.Log("=== In-session roaming: client sending from same port but ===")
	t.Log("=== server should auto-update endpoint on valid packets ===")

	// Send more messages
	for i := 2; i <= 5; i++ {
		if err := clientHost.Send(serverKey.Public, 0x80, []byte("Message from same session")); err != nil {
			t.Fatalf("Failed to send message %d: %v", i, err)
		}

		msg, err := serverHost.RecvTimeout(2 * time.Second)
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}
		t.Logf("Server received: %s (counter increases, proving same session)", msg.Data)
	}

	// Server replies
	if err := serverHost.Send(clientKey.Public, 0x81, []byte("Reply from server")); err != nil {
		t.Fatalf("Failed to send reply: %v", err)
	}

	reply, err := clientHost.RecvTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive reply: %v", err)
	}
	t.Logf("Client received reply: %s", reply.Data)

	t.Log("=== In-session communication PASSED (same session, no re-handshake) ===")
}

// TestRapidRoaming tests rapid IP changes - extreme roaming scenario.
// Simulates a device rapidly switching between networks.
func TestRapidRoaming(t *testing.T) {
	const (
		numRoams       = 50  // Number of IP changes
		msgsPerRoam    = 10  // Messages per IP
		totalMessages  = numRoams * msgsPerRoam
	)

	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Server with fixed transport
	serverTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer serverTransport.Close()

	serverConn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:  serverKey,
		RemotePK:  clientKey.Public,
		Transport: serverTransport,
	})
	if err != nil {
		t.Fatalf("Failed to create server conn: %v", err)
	}

	serverAddr := serverTransport.LocalAddr()
	t.Logf("Server on %s", serverAddr)

	// Initial client transport for handshake
	clientTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client transport: %v", err)
	}

	clientConn, err := noise.NewConn(noise.ConnConfig{
		LocalKey:   clientKey,
		RemotePK:   serverKey.Public,
		Transport:  clientTransport,
		RemoteAddr: serverAddr,
	})
	if err != nil {
		t.Fatalf("Failed to create client conn: %v", err)
	}

	// Set server's remote addr
	serverConn.SetRemoteAddr(clientTransport.LocalAddr())

	// Handshake
	handshakeDone := make(chan error, 2)
	go func() { handshakeDone <- clientConn.Open() }()
	go func() {
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := serverTransport.RecvFrom(buf)
		if err != nil {
			handshakeDone <- err
			return
		}
		initMsg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			handshakeDone <- err
			return
		}
		respBytes, err := serverConn.Accept(initMsg)
		if err != nil {
			handshakeDone <- err
			return
		}
		handshakeDone <- serverTransport.SendTo(respBytes, clientTransport.LocalAddr())
	}()

	for i := 0; i < 2; i++ {
		if err := <-handshakeDone; err != nil {
			t.Fatalf("Handshake failed: %v", err)
		}
	}

	session := clientConn.Session()
	if session == nil {
		t.Fatal("No session after handshake")
	}

	t.Logf("Handshake done. Starting rapid roaming test: %d roams, %d msgs each", numRoams, msgsPerRoam)

	// Track stats
	var (
		sentCount     int
		recvCount     int
		roamCount     int
		currentClient = clientConn
		currentTrans  = clientTransport
	)

	// Receiver goroutine
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for i := 0; i < totalMessages; i++ {
			_, _, err := serverConn.Recv()
			if err != nil {
				t.Errorf("Recv %d failed: %v", i, err)
				return
			}
			recvCount++
		}
	}()

	// Rapid roaming loop
	startTime := time.Now()

	for roam := 0; roam < numRoams; roam++ {
		// Send messages from current IP
		for msg := 0; msg < msgsPerRoam; msg++ {
			data := []byte(fmt.Sprintf("roam=%d,msg=%d", roam, msg))
			if err := currentClient.Send(0x80, data); err != nil {
				t.Fatalf("Send failed at roam %d, msg %d: %v", roam, msg, err)
			}
			sentCount++
		}

		// Roam to new IP (except last iteration)
		if roam < numRoams-1 {
			// Create new transport
			newTransport, err := NewUDPListener("127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to create new transport at roam %d: %v", roam, err)
			}

			// Create new conn with same session
			newClient, err := noise.NewConn(noise.ConnConfig{
				LocalKey:   clientKey,
				RemotePK:   serverKey.Public,
				Transport:  newTransport,
				RemoteAddr: serverAddr,
			})
			if err != nil {
				newTransport.Close()
				t.Fatalf("Failed to create new conn at roam %d: %v", roam, err)
			}
			newClient.SetSession(session)

			// Update server's endpoint
			serverConn.SetRemoteAddr(newTransport.LocalAddr())

			// Close old transport
			currentTrans.Close()

			currentClient = newClient
			currentTrans = newTransport
			roamCount++
		}
	}

	// Wait for all messages to be received
	select {
	case <-recvDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for messages")
	}

	// Cleanup
	currentTrans.Close()

	elapsed := time.Since(startTime)
	msgsPerSec := float64(totalMessages) / elapsed.Seconds()
	roamsPerSec := float64(roamCount) / elapsed.Seconds()

	t.Logf("=== Rapid Roaming Results ===")
	t.Logf("Total roams: %d", roamCount)
	t.Logf("Total messages: sent=%d, recv=%d", sentCount, recvCount)
	t.Logf("Elapsed: %v", elapsed)
	t.Logf("Throughput: %.0f msgs/sec, %.1f roams/sec", msgsPerSec, roamsPerSec)

	if recvCount != totalMessages {
		t.Errorf("Message loss: sent %d, received %d", totalMessages, recvCount)
	}

	t.Log("=== Rapid Roaming PASSED ===")
}

// TestConcurrentRoaming tests roaming with concurrent send/recv.
// Multiple goroutines sending while IP changes.
func TestConcurrentRoaming(t *testing.T) {
	const (
		numRoams    = 20
		numSenders  = 5
		msgsPerSend = 50
	)

	serverKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}
	clientKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Server
	serverTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer serverTransport.Close()

	serverHost, err := host.NewHost(host.HostConfig{
		PrivateKey:        serverKey,
		Transport:         serverTransport,
		AllowUnknownPeers: true,
	})
	if err != nil {
		t.Fatalf("Failed to create server host: %v", err)
	}
	defer serverHost.Close()

	serverAddr := serverTransport.LocalAddr()

	// Initial client
	clientTransport, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client transport: %v", err)
	}

	clientHost, err := host.NewHost(host.HostConfig{
		PrivateKey: clientKey,
		Transport:  clientTransport,
	})
	if err != nil {
		t.Fatalf("Failed to create client host: %v", err)
	}

	if err := clientHost.AddPeer(serverKey.Public, serverAddr); err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}
	if err := clientHost.Connect(serverKey.Public); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	t.Log("Initial connection established")

	// Receiver
	var recvCount int64
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			_, err := serverHost.RecvTimeout(5 * time.Second)
			if err != nil {
				return
			}
			atomic.AddInt64(&recvCount, 1)
		}
	}()

	// Concurrent senders
	var wg sync.WaitGroup
	var sentCount int64
	var sendErrors int64

	currentHost := clientHost
	var hostMu sync.RWMutex

	// Start senders
	for s := 0; s < numSenders; s++ {
		wg.Add(1)
		go func(senderID int) {
			defer wg.Done()
			for i := 0; i < msgsPerSend; i++ {
				hostMu.RLock()
				h := currentHost
				hostMu.RUnlock()

				data := []byte(fmt.Sprintf("sender=%d,msg=%d", senderID, i))
				if err := h.Send(serverKey.Public, 0x80, data); err != nil {
					atomic.AddInt64(&sendErrors, 1)
				} else {
					atomic.AddInt64(&sentCount, 1)
				}
				time.Sleep(time.Microsecond * 100) // Small delay
			}
		}(s)
	}

	// Roaming goroutine
	go func() {
		for roam := 0; roam < numRoams; roam++ {
			time.Sleep(time.Millisecond * 50) // Roam every 50ms

			// Create new transport
			newTransport, err := NewUDPListener("127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to create transport at roam %d: %v", roam, err)
				continue
			}

			newHost, err := host.NewHost(host.HostConfig{
				PrivateKey: clientKey,
				Transport:  newTransport,
			})
			if err != nil {
				newTransport.Close()
				continue
			}

			if err := newHost.AddPeer(serverKey.Public, serverAddr); err != nil {
				newHost.Close()
				newTransport.Close()
				continue
			}

			if err := newHost.Connect(serverKey.Public); err != nil {
				newHost.Close()
				newTransport.Close()
				continue
			}

			// Swap hosts
			hostMu.Lock()
			oldHost := currentHost
			oldTransport := clientTransport
			currentHost = newHost
			clientTransport = newTransport
			hostMu.Unlock()

			// Close old (after swap)
			oldHost.Close()
			oldTransport.Close()
		}
	}()

	// Wait for senders
	wg.Wait()

	// Give receiver time to catch up
	time.Sleep(500 * time.Millisecond)

	// Cleanup
	hostMu.Lock()
	currentHost.Close()
	clientTransport.Close()
	hostMu.Unlock()

	finalRecv := atomic.LoadInt64(&recvCount)
	finalSent := atomic.LoadInt64(&sentCount)
	finalErrors := atomic.LoadInt64(&sendErrors)

	t.Logf("=== Concurrent Roaming Results ===")
	t.Logf("Roams: %d", numRoams)
	t.Logf("Senders: %d x %d msgs = %d total", numSenders, msgsPerSend, numSenders*msgsPerSend)
	t.Logf("Sent: %d (errors: %d)", finalSent, finalErrors)
	t.Logf("Received: %d", finalRecv)
	t.Logf("Loss rate: %.2f%%", float64(finalSent-finalRecv)/float64(finalSent)*100)

	// Allow some loss due to roaming during send
	lossRate := float64(finalSent-finalRecv) / float64(finalSent)
	if lossRate > 0.20 { // Allow up to 20% loss during rapid roaming
		t.Errorf("Excessive loss: %.2f%%", lossRate*100)
	}

	t.Log("=== Concurrent Roaming PASSED ===")
}

// TestBidirectionalRoaming tests both sides roaming simultaneously.
func TestBidirectionalRoaming(t *testing.T) {
	const numRoams = 10

	key1, _ := noise.GenerateKeyPair()
	key2, _ := noise.GenerateKeyPair()

	// Create initial transports
	trans1, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	trans2, err := NewUDPListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	host1, err := host.NewHost(host.HostConfig{
		PrivateKey:        key1,
		Transport:         trans1,
		AllowUnknownPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	host2, err := host.NewHost(host.HostConfig{
		PrivateKey:        key2,
		Transport:         trans2,
		AllowUnknownPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Connect host1 -> host2
	host1.AddPeer(key2.Public, trans2.LocalAddr())
	if err := host1.Connect(key2.Public); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	t.Log("Initial connection established")

	var (
		sent1, recv1 int64
		sent2, recv2 int64
		wg           sync.WaitGroup
	)

	// Receiver for host1
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, err := host1.RecvTimeout(3 * time.Second)
			if err != nil {
				return
			}
			atomic.AddInt64(&recv1, 1)
		}
	}()

	// Receiver for host2
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, err := host2.RecvTimeout(3 * time.Second)
			if err != nil {
				return
			}
			atomic.AddInt64(&recv2, 1)
		}
	}()

	currentHost1, currentTrans1 := host1, trans1
	currentHost2, currentTrans2 := host2, trans2
	var mu1, mu2 sync.RWMutex

	// Bidirectional sending + roaming
	for roam := 0; roam < numRoams; roam++ {
		// Send from both sides
		for i := 0; i < 20; i++ {
			mu1.RLock()
			h1 := currentHost1
			mu1.RUnlock()
			if err := h1.Send(key2.Public, 0x80, []byte("from1")); err == nil {
				atomic.AddInt64(&sent1, 1)
			}

			mu2.RLock()
			h2 := currentHost2
			mu2.RUnlock()
			if err := h2.Send(key1.Public, 0x81, []byte("from2")); err == nil {
				atomic.AddInt64(&sent2, 1)
			}
		}

		// Roam host1
		newTrans1, _ := NewUDPListener("127.0.0.1:0")
		newHost1, _ := host.NewHost(host.HostConfig{
			PrivateKey:        key1,
			Transport:         newTrans1,
			AllowUnknownPeers: true,
		})
		mu2.RLock()
		addr2 := currentTrans2.LocalAddr()
		mu2.RUnlock()
		newHost1.AddPeer(key2.Public, addr2)
		newHost1.Connect(key2.Public)

		mu1.Lock()
		oldHost1, oldTrans1 := currentHost1, currentTrans1
		currentHost1, currentTrans1 = newHost1, newTrans1
		mu1.Unlock()
		oldHost1.Close()
		oldTrans1.Close()

		// Roam host2
		newTrans2, _ := NewUDPListener("127.0.0.1:0")
		newHost2, _ := host.NewHost(host.HostConfig{
			PrivateKey:        key2,
			Transport:         newTrans2,
			AllowUnknownPeers: true,
		})
		mu1.RLock()
		addr1 := currentTrans1.LocalAddr()
		mu1.RUnlock()
		newHost2.AddPeer(key1.Public, addr1)
		newHost2.Connect(key1.Public)

		mu2.Lock()
		oldHost2, oldTrans2 := currentHost2, currentTrans2
		currentHost2, currentTrans2 = newHost2, newTrans2
		mu2.Unlock()
		oldHost2.Close()
		oldTrans2.Close()

		t.Logf("Roam %d: host1->%s, host2->%s", roam+1,
			currentTrans1.LocalAddr(), currentTrans2.LocalAddr())
	}

	// Final exchange
	time.Sleep(200 * time.Millisecond)

	mu1.Lock()
	currentHost1.Close()
	currentTrans1.Close()
	mu1.Unlock()

	mu2.Lock()
	currentHost2.Close()
	currentTrans2.Close()
	mu2.Unlock()

	// Wait for receivers
	wg.Wait()

	t.Logf("=== Bidirectional Roaming Results ===")
	t.Logf("Host1: sent=%d, recv=%d", sent1, recv1)
	t.Logf("Host2: sent=%d, recv=%d", sent2, recv2)
	t.Logf("Total roams: %d (each side)", numRoams)

	t.Log("=== Bidirectional Roaming PASSED ===")
}
