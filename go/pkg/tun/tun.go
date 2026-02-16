// Package tun provides a cross-platform TUN device interface.
//
// This package wraps the Zig TUN library via CGo, providing
// a native Go API for creating and managing TUN devices.
package tun

/*
#cgo CFLAGS: -I${SRCDIR}/../../../zig/include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ltun -framework CoreFoundation -framework SystemConfiguration
#cgo linux LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ltun
#cgo windows LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ltun -lws2_32 -liphlpapi

#include "tun.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Error codes
var (
	ErrCreateFailed     = errors.New("tun: create failed")
	ErrOpenFailed       = errors.New("tun: open failed")
	ErrInvalidName      = errors.New("tun: invalid name")
	ErrPermissionDenied = errors.New("tun: permission denied")
	ErrDeviceNotFound   = errors.New("tun: device not found")
	ErrNotSupported     = errors.New("tun: not supported")
	ErrDeviceBusy       = errors.New("tun: device busy")
	ErrInvalidArgument  = errors.New("tun: invalid argument")
	ErrSystemResources  = errors.New("tun: system resources exhausted")
	ErrWouldBlock       = errors.New("tun: would block")
	ErrIO               = errors.New("tun: I/O error")
	ErrSetMTUFailed     = errors.New("tun: set MTU failed")
	ErrSetAddressFailed = errors.New("tun: set address failed")
	ErrSetStateFailed   = errors.New("tun: set state failed")
	ErrAlreadyClosed    = errors.New("tun: already closed")
	ErrWintunNotFound   = errors.New("tun: wintun not found")
	ErrWintunInitFailed = errors.New("tun: wintun init failed")
)

var initOnce sync.Once
var initErr error

// Init initializes the TUN subsystem.
// On Windows, this loads the Wintun driver.
// On Unix systems, this is a no-op but should be called for portability.
func Init() error {
	initOnce.Do(func() {
		rc := C.tun_init()
		if rc != 0 {
			initErr = codeToError(int(rc))
		}
	})
	return initErr
}

// Deinit cleans up the TUN subsystem.
// On Windows, this unloads the Wintun driver.
func Deinit() {
	C.tun_deinit()
}

// Device represents a TUN device.
// It is safe for concurrent use from multiple goroutines.
//
// Close/Read synchronization: Read may block inside a kernel syscall
// (C.tun_read). Close must close the fd to unblock it. We use an atomic
// flag instead of a mutex to avoid deadlocking Close on a blocked Read.
type Device struct {
	handle *C.tun_t
	name   string
	closed atomic.Bool
}

// Create creates a new TUN device.
// If name is empty, the system will auto-assign a name.
func Create(name string) (*Device, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	var cname *C.char
	if name != "" {
		cname = C.CString(name)
		defer C.free(unsafe.Pointer(cname))
	}

	handle := C.tun_create(cname)
	if handle == nil {
		return nil, ErrCreateFailed
	}

	// Get the assigned name
	cDevName := C.tun_get_name(handle)
	devName := ""
	if cDevName != nil {
		devName = C.GoString(cDevName)
	}

	return &Device{
		handle: handle,
		name:   devName,
	}, nil
}

// Close closes the TUN device.
//
// Marks the device as closed (atomic), then closes the fd. The fd close
// unblocks any goroutine stuck in C.tun_read/C.tun_write. Those calls
// return an error, and the caller sees d.closed == true.
//
// No mutex — Read/Write may be blocked in a kernel syscall holding a
// lock, so acquiring any lock here would deadlock.
func (d *Device) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return ErrAlreadyClosed
	}
	// Close the fd. This unblocks blocked Read/Write C calls.
	C.tun_close(d.handle)
	return nil
}

// Read reads a packet from the TUN device.
// The packet is a raw IP packet (IPv4 or IPv6).
func (d *Device) Read(buf []byte) (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(buf) == 0 {
		return 0, nil
	}

	n := C.tun_read(d.handle, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if n < 0 {
		// If closed while we were blocked in the syscall, report cleanly.
		if d.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		return 0, codeToError(int(n))
	}
	return int(n), nil
}

// Write writes a packet to the TUN device.
// The packet should be a valid IP packet (IPv4 or IPv6).
func (d *Device) Write(buf []byte) (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(buf) == 0 {
		return 0, nil
	}

	n := C.tun_write(d.handle, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if n < 0 {
		if d.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		return 0, codeToError(int(n))
	}
	return int(n), nil
}

// Name returns the device name.
func (d *Device) Name() string {
	return d.name
}

// Handle returns the underlying file descriptor (Unix) or HANDLE (Windows).
func (d *Device) Handle() int {
	if d.closed.Load() {
		return -1
	}
	return int(C.tun_get_handle(d.handle))
}

// MTU returns the MTU (Maximum Transmission Unit).
func (d *Device) MTU() (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	mtu := C.tun_get_mtu(d.handle)
	if mtu < 0 {
		return 0, codeToError(int(mtu))
	}
	return int(mtu), nil
}

// SetMTU sets the MTU. Requires root/admin privileges.
func (d *Device) SetMTU(mtu int) error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	rc := C.tun_set_mtu(d.handle, C.int(mtu))
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// SetNonblocking sets non-blocking mode.
func (d *Device) SetNonblocking(enabled bool) error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	flag := 0
	if enabled {
		flag = 1
	}
	rc := C.tun_set_nonblocking(d.handle, C.int(flag))
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// Up brings the interface up. Requires root/admin privileges.
func (d *Device) Up() error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	rc := C.tun_set_up(d.handle)
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// Down brings the interface down. Requires root/admin privileges.
func (d *Device) Down() error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	rc := C.tun_set_down(d.handle)
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// SetIPv4 sets the IPv4 address and netmask. Requires root/admin privileges.
func (d *Device) SetIPv4(addr net.IP, mask net.IPMask) error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	ip4 := addr.To4()
	if ip4 == nil {
		return ErrInvalidArgument
	}
	if len(mask) != 4 {
		return ErrInvalidArgument
	}
	cAddr := C.CString(ip4.String())
	defer C.free(unsafe.Pointer(cAddr))
	cMask := C.CString(net.IP(mask).String())
	defer C.free(unsafe.Pointer(cMask))

	rc := C.tun_set_ipv4(d.handle, cAddr, cMask)
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// SetIPv6 sets the IPv6 address with prefix length. Requires root/admin privileges.
func (d *Device) SetIPv6(addr net.IP, prefixLen int) error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	ip6 := addr.To16()
	if ip6 == nil || ip6.To4() != nil {
		return ErrInvalidArgument
	}
	if prefixLen < 0 || prefixLen > 128 {
		return ErrInvalidArgument
	}
	cAddr := C.CString(ip6.String())
	defer C.free(unsafe.Pointer(cAddr))

	rc := C.tun_set_ipv6(d.handle, cAddr, C.int(prefixLen))
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// codeToError converts a C error code to a Go error.
func codeToError(code int) error {
	switch code {
	case 0:
		return nil
	case -1:
		return ErrCreateFailed
	case -2:
		return ErrOpenFailed
	case -3:
		return ErrInvalidName
	case -4:
		return ErrPermissionDenied
	case -5:
		return ErrDeviceNotFound
	case -6:
		return ErrNotSupported
	case -7:
		return ErrDeviceBusy
	case -8:
		return ErrInvalidArgument
	case -9:
		return ErrSystemResources
	case -10:
		return ErrWouldBlock
	case -11:
		return ErrIO
	case -12:
		return ErrSetMTUFailed
	case -13:
		return ErrSetAddressFailed
	case -14:
		return ErrSetStateFailed
	case -15:
		return ErrAlreadyClosed
	case -16:
		return ErrWintunNotFound
	case -17:
		return ErrWintunInitFailed
	default:
		return fmt.Errorf("tun: unknown error code %d", code)
	}
}
