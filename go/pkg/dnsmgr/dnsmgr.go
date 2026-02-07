// Package dnsmgr provides OS-level DNS configuration management.
//
// This package wraps the Zig dnsmgr library via CGo, providing a native
// Go API for configuring the operating system to route DNS queries for
// specific domains to a custom nameserver (e.g., the Magic DNS server).
//
// Platform support:
//   - macOS: /etc/resolver/ files (native split DNS)
//   - Linux: systemd-resolved or /etc/resolv.conf
//   - Windows: NRPT registry rules
package dnsmgr

/*
#cgo CFLAGS: -I${SRCDIR}/../../../zig/include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ldnsmgr -framework CoreFoundation -framework SystemConfiguration
#cgo linux LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ldnsmgr
#cgo windows LDFLAGS: -L${SRCDIR}/../../../zig/zig-out/lib -ldnsmgr -ladvapi32

#include "dnsmgr.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

// Error codes.
var (
	ErrSetFailed        = errors.New("dnsmgr: set DNS failed")
	ErrCreateFailed     = errors.New("dnsmgr: create failed")
	ErrRemoveFailed     = errors.New("dnsmgr: remove failed")
	ErrPermissionDenied = errors.New("dnsmgr: permission denied")
	ErrNotSupported     = errors.New("dnsmgr: not supported")
	ErrInvalidArgument  = errors.New("dnsmgr: invalid argument")
	ErrFlushFailed      = errors.New("dnsmgr: flush cache failed")
	ErrDetectFailed     = errors.New("dnsmgr: detect DNS mode failed")
	ErrUpstreamFailed   = errors.New("dnsmgr: upstream operation failed")
)

// Manager manages OS DNS configuration.
// It is safe for concurrent use from multiple goroutines.
type Manager struct {
	handle *C.dnsmgr_t
	mu     sync.RWMutex
	closed bool
}

// New creates a new DNS manager.
// ifaceName is the TUN interface name (e.g., "utun3", "tun0").
// Pass "" if not applicable.
func New(ifaceName string) (*Manager, error) {
	var cName *C.char
	if ifaceName != "" {
		cName = C.CString(ifaceName)
		defer C.free(unsafe.Pointer(cName))
	}

	handle := C.dnsmgr_create(cName)
	if handle == nil {
		return nil, ErrCreateFailed
	}

	return &Manager{handle: handle}, nil
}

// SetDNS configures the OS to route queries for the given domains
// to the specified nameserver.
//
// nameserver is an IP address (e.g., "100.64.0.1").
// domains is a list of domain suffixes (e.g., ["zigor.net"]).
func (m *Manager) SetDNS(nameserver string, domains []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrSetFailed
	}

	cNS := C.CString(nameserver)
	defer C.free(unsafe.Pointer(cNS))

	csv := strings.Join(domains, ",")
	cDomains := C.CString(csv)
	defer C.free(unsafe.Pointer(cDomains))

	rc := C.dnsmgr_set(m.handle, cNS, cDomains)
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// SupportsSplitDNS reports whether the platform supports split DNS natively.
func (m *Manager) SupportsSplitDNS() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false
	}

	return C.dnsmgr_supports_split_dns(m.handle) != 0
}

// FlushCache clears the OS DNS cache.
func FlushCache() error {
	rc := C.dnsmgr_flush_cache()
	if rc != 0 {
		return codeToError(int(rc))
	}
	return nil
}

// Close restores the original DNS configuration and releases resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	C.dnsmgr_close(m.handle)
	m.handle = nil
	m.closed = true
	return nil
}

// codeToError converts a C error code to a Go error.
func codeToError(code int) error {
	switch code {
	case 0:
		return nil
	case -1:
		return ErrSetFailed
	case -2:
		return ErrCreateFailed
	case -3:
		return ErrRemoveFailed
	case -4:
		return ErrPermissionDenied
	case -5:
		return ErrNotSupported
	case -6:
		return ErrInvalidArgument
	case -7:
		return ErrFlushFailed
	case -8:
		return ErrDetectFailed
	case -9:
		return ErrUpstreamFailed
	default:
		return fmt.Errorf("dnsmgr: unknown error code %d", code)
	}
}
