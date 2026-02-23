//go:build linux

package net

import (
	"encoding/binary"
	"net"
	"syscall"
)

// sendToGSO sends a message using GSO (Generic Segmentation Offload).
// Uses sendmsg with UDP_SEGMENT cmsg to enable per-send segmentation.
// Only works on Linux 4.18+ with supported NICs.
func (u *UDP) sendToGSO(data []byte, addr *net.UDPAddr) (int, error) {
	// Get raw file descriptor
	rawConn, err := u.socket.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var sendErr error

	rawConn.Control(func(fd uintptr) {
		// Prepare cmsg: cmsghdr + uint16 segment size
		// cmsg format: { level, type, len, data }
		const cmsgSize = 16 // sizeof(cmsghdr) + sizeof(uint16) + padding
		var cmsgBuf [cmsgSize]byte

		// Fill cmsghdr (platform-specific layout)
		// On Linux: { len (4), level (4), type (4) }
		binary.LittleEndian.PutUint32(cmsgBuf[0:4], cmsgSize)
		binary.LittleEndian.PutUint32(cmsgBuf[4:8], syscall.IPPROTO_UDP)
		binary.LittleEndian.PutUint32(cmsgBuf[8:12], 103) // UDP_SEGMENT
		binary.LittleEndian.PutUint16(cmsgBuf[12:14], uint16(DefaultGSOSegment))

		// Send via sendmsg using syscall
		var sa syscall.Sockaddr
		if addr.IP.To4() != nil {
			sa4 := &syscall.SockaddrInet4{Port: addr.Port}
			copy(sa4.Addr[:], addr.IP.To4())
			sa = sa4
		} else {
			sa6 := &syscall.SockaddrInet6{Port: addr.Port}
			copy(sa6.Addr[:], addr.IP)
			sa = sa6
		}

		n, sendErr = syscall.SendmsgN(int(fd), data, cmsgBuf[:], sa, 0)
	})

	if sendErr != nil {
		return 0, sendErr
	}
	return n, nil
}
