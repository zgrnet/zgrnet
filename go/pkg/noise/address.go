package noise

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Address type constants (SOCKS5 compatible).
const (
	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x03
	AddressTypeIPv6   byte = 0x04
)

// Address represents a network address with type, host, and port.
// Wire format: atyp(1B) | addr(var) | port(2B BE)
//
//	atyp=0x01: IPv4, addr=4 bytes
//	atyp=0x03: Domain, addr=1 byte len + string
//	atyp=0x04: IPv6, addr=16 bytes
type Address struct {
	Type byte   // AddressTypeIPv4, AddressTypeDomain, or AddressTypeIPv6
	Host string // IP address string or domain name
	Port uint16
}

// Encode serializes the address to bytes.
func (a *Address) Encode() []byte {
	switch a.Type {
	case AddressTypeIPv4:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil
		}
		buf := make([]byte, 1+4+2)
		buf[0] = AddressTypeIPv4
		copy(buf[1:5], ip4)
		binary.BigEndian.PutUint16(buf[5:7], a.Port)
		return buf

	case AddressTypeDomain:
		if len(a.Host) == 0 || len(a.Host) > 255 {
			return nil
		}
		buf := make([]byte, 1+1+len(a.Host)+2)
		buf[0] = AddressTypeDomain
		buf[1] = byte(len(a.Host))
		copy(buf[2:2+len(a.Host)], a.Host)
		binary.BigEndian.PutUint16(buf[2+len(a.Host):], a.Port)
		return buf

	case AddressTypeIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil
		}
		ip6 := ip.To16()
		buf := make([]byte, 1+16+2)
		buf[0] = AddressTypeIPv6
		copy(buf[1:17], ip6)
		binary.BigEndian.PutUint16(buf[17:19], a.Port)
		return buf

	default:
		return nil
	}
}

// DecodeAddress parses an Address from data.
// Returns the address, number of bytes consumed, and any error.
func DecodeAddress(data []byte) (*Address, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrInvalidAddress
	}

	atyp := data[0]
	switch atyp {
	case AddressTypeIPv4:
		if len(data) < 1+4+2 {
			return nil, 0, ErrInvalidAddress
		}
		ip := net.IP(data[1:5])
		port := binary.BigEndian.Uint16(data[5:7])
		return &Address{
			Type: AddressTypeIPv4,
			Host: ip.String(),
			Port: port,
		}, 7, nil

	case AddressTypeDomain:
		if len(data) < 2 {
			return nil, 0, ErrInvalidAddress
		}
		domainLen := int(data[1])
		if domainLen == 0 || len(data) < 2+domainLen+2 {
			return nil, 0, ErrInvalidAddress
		}
		host := string(data[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(data[2+domainLen : 4+domainLen])
		return &Address{
			Type: AddressTypeDomain,
			Host: host,
			Port: port,
		}, 2 + domainLen + 2, nil

	case AddressTypeIPv6:
		if len(data) < 1+16+2 {
			return nil, 0, ErrInvalidAddress
		}
		ip := net.IP(data[1:17])
		port := binary.BigEndian.Uint16(data[17:19])
		return &Address{
			Type: AddressTypeIPv6,
			Host: ip.String(),
			Port: port,
		}, 19, nil

	default:
		return nil, 0, fmt.Errorf("noise: unknown address type 0x%02x", atyp)
	}
}
