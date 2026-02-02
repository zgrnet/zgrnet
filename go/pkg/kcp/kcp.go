package kcp

/*
#cgo CFLAGS: -O3
#include "ikcp.h"
#include <stdlib.h>

// Forward declaration for Go callback
extern int goKcpOutput(char *buf, int len, void *user);

static int kcp_output_wrapper(const char *buf, int len, ikcpcb *kcp, void *user) {
    return goKcpOutput((char*)buf, len, user);
}

static void kcp_set_output(ikcpcb *kcp) {
    ikcp_setoutput(kcp, kcp_output_wrapper);
}
*/
import "C"
import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// KCP represents a KCP control block.
type KCP struct {
	kcp      *C.ikcpcb
	conv     uint32
	id       uint64 // Unique ID for callback identification
	userData *kcpUserData
	mu       sync.Mutex
	outputFn func([]byte)
}

// Global registry for KCP instances (needed for cgo callback)
var (
	kcpRegistry   = make(map[uint64]*KCP)
	kcpRegistryMu sync.RWMutex
	kcpNextID     uint64
)

// kcpUserData holds an ID for safe pointer passing to C.
// This avoids checkptr issues by using a real Go-allocated pointer.
type kcpUserData struct {
	id uint64
}

//export goKcpOutput
func goKcpOutput(buf *C.char, length C.int, user unsafe.Pointer) C.int {
	if user == nil {
		return 0
	}
	ud := (*kcpUserData)(user)

	kcpRegistryMu.RLock()
	k, ok := kcpRegistry[ud.id]
	kcpRegistryMu.RUnlock()

	if !ok || k.outputFn == nil {
		return 0
	}

	data := C.GoBytes(unsafe.Pointer(buf), length)
	k.outputFn(data)
	return 0
}

// NewKCP creates a new KCP instance with the given conversation ID.
func NewKCP(conv uint32, output func([]byte)) *KCP {
	// Generate unique ID
	id := atomic.AddUint64(&kcpNextID, 1)

	// Create user data struct (Go-allocated, safe pointer)
	ud := &kcpUserData{id: id}

	k := &KCP{
		conv:     conv,
		id:       id,
		userData: ud,
		outputFn: output,
	}

	// Register in global map first
	kcpRegistryMu.Lock()
	kcpRegistry[id] = k
	kcpRegistryMu.Unlock()

	// Create KCP with real Go pointer as user data
	k.kcp = C.ikcp_create(C.IUINT32(conv), unsafe.Pointer(ud))

	// Set output callback
	C.kcp_set_output(k.kcp)

	return k
}

// Release frees the KCP instance.
func (k *KCP) Release() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp != nil {
		// Unregister from global map
		kcpRegistryMu.Lock()
		delete(kcpRegistry, k.id)
		kcpRegistryMu.Unlock()

		C.ikcp_release(k.kcp)
		k.kcp = nil
		k.userData = nil
	}
}

// Send sends data through KCP (upper level send).
// Returns bytes sent or error code.
func (k *KCP) Send(data []byte) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil || len(data) == 0 {
		return -1
	}

	return int(C.ikcp_send(k.kcp, (*C.char)(unsafe.Pointer(&data[0])), C.int(len(data))))
}

// Recv receives data from KCP (upper level recv).
// Returns bytes received, or negative error code.
func (k *KCP) Recv(buf []byte) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil || len(buf) == 0 {
		return -1
	}

	return int(C.ikcp_recv(k.kcp, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))))
}

// Input processes a received lower-level packet.
func (k *KCP) Input(data []byte) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil || len(data) == 0 {
		return -1
	}

	return int(C.ikcp_input(k.kcp, (*C.char)(unsafe.Pointer(&data[0])), C.long(len(data))))
}

// Update updates the KCP state. Call it periodically (every 10ms-100ms).
// current is the current timestamp in milliseconds.
func (k *KCP) Update(current uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp != nil {
		C.ikcp_update(k.kcp, C.IUINT32(current))
	}
}

// Check returns when you should call Update next.
// Returns timestamp in milliseconds.
func (k *KCP) Check(current uint32) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return current
	}

	return uint32(C.ikcp_check(k.kcp, C.IUINT32(current)))
}

// Flush flushes pending data.
func (k *KCP) Flush() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp != nil {
		C.ikcp_flush(k.kcp)
	}
}

// PeekSize returns the size of the next message in the recv queue.
// Returns negative if no message is available.
func (k *KCP) PeekSize() int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return -1
	}

	return int(C.ikcp_peeksize(k.kcp))
}

// SetMTU sets the maximum transmission unit size.
func (k *KCP) SetMTU(mtu int) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return -1
	}

	return int(C.ikcp_setmtu(k.kcp, C.int(mtu)))
}

// SetWndSize sets the send and receive window sizes.
func (k *KCP) SetWndSize(sndwnd, rcvwnd int) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return -1
	}

	return int(C.ikcp_wndsize(k.kcp, C.int(sndwnd), C.int(rcvwnd)))
}

// SetNodelay configures KCP for low latency or high throughput.
//
// nodelay: 0=disable(default), 1=enable
// interval: internal update timer interval in ms, default is 100ms
// resend: 0=disable fast resend(default), 1=enable fast resend
// nc: 0=normal congestion control(default), 1=disable congestion control
//
// For fastest mode: SetNodelay(1, 10, 2, 1)
// For normal mode: SetNodelay(0, 100, 0, 0)
func (k *KCP) SetNodelay(nodelay, interval, resend, nc int) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return -1
	}

	return int(C.ikcp_nodelay(k.kcp, C.int(nodelay), C.int(interval), C.int(resend), C.int(nc)))
}

// WaitSnd returns the number of packets waiting to be sent.
func (k *KCP) WaitSnd() int {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.kcp == nil {
		return 0
	}

	return int(C.ikcp_waitsnd(k.kcp))
}

// Conv returns the conversation ID.
func (k *KCP) Conv() uint32 {
	return k.conv
}

// SetOutput changes the output callback.
func (k *KCP) SetOutput(output func([]byte)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.outputFn = output
}

// GetConv extracts the conversation ID from a KCP packet.
func GetConv(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return uint32(C.ikcp_getconv(unsafe.Pointer(&data[0])))
}

// DefaultConfig sets KCP to fast mode with reasonable defaults.
func (k *KCP) DefaultConfig() {
	k.SetNodelay(1, 1, 2, 1)   // Fast mode with 1ms interval
	k.SetWndSize(4096, 4096)   // Large window for high throughput
	k.SetMTU(1400)             // Standard MTU
}
