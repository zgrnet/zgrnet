//go:build linux

package net

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendToGSO sends a message using GSO (Generic Segmentation Offload).
// Uses sendmsg with UDP_SEGMENT cmsg to enable per-send segmentation.
// Only works on Linux 4.18+ with supported NICs.
func (u *UDP) sendToGSO(data []byte, addr *net.UDPAddr) (int, error) {
	rawConn, err := u.socket.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var sendErr error

	rawConn.Control(func(fd uintptr) {
		// Prepare cmsg buffer using unix.CmsgSpace for correct alignment
		// UDP_SEGMENT expects a uint16 segment size
		cmsgBuf := make([]byte, unix.CmsgSpace(2))

		// Fill cmsghdr using unix.CmsgLen for correct length
		cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgBuf[0]))
		cmsg.Level = unix.IPPROTO_UDP
		cmsg.Type = unix.UDP_SEGMENT
		cmsg.Len = uint64(unix.CmsgLen(2))

		// Write segment size (uint16) into cmsg data area
		// unix.CmsgData returns unsafe.Pointer to the data portion
		dataPtr := unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + unix.SizeofCmsghdr)
		dataBuf := (*[2]byte)(dataPtr)
		binary.LittleEndian.PutUint16(dataBuf[:], uint16(DefaultGSOSegment))

		// Prepare sockaddr
		var sa unix.Sockaddr
		if addr.IP.To4() != nil {
			sa4 := &unix.SockaddrInet4{Port: addr.Port}
			copy(sa4.Addr[:], addr.IP.To4())
			sa = sa4
		} else {
			sa6 := &unix.SockaddrInet6{Port: addr.Port}
			copy(sa6.Addr[:], addr.IP)
			sa = sa6
		}

		n, sendErr = unix.SendmsgN(int(fd), data, cmsgBuf, sa, 0)
	})

	if sendErr != nil {
		return 0, sendErr
	}
	return n, nil
}
