package noise

import (
	"testing"
)

func TestAddressIPv4(t *testing.T) {
	addr := &Address{Type: AddressTypeIPv4, Host: "192.168.1.1", Port: 8080}
	encoded := addr.Encode()
	if encoded == nil {
		t.Fatal("Encode returned nil")
	}
	if len(encoded) != 7 { // 1 + 4 + 2
		t.Fatalf("expected 7 bytes, got %d", len(encoded))
	}
	if encoded[0] != AddressTypeIPv4 {
		t.Fatalf("expected type 0x01, got 0x%02x", encoded[0])
	}

	decoded, n, err := DecodeAddress(encoded)
	if err != nil {
		t.Fatalf("DecodeAddress error: %v", err)
	}
	if n != 7 {
		t.Fatalf("expected consumed 7, got %d", n)
	}
	if decoded.Type != AddressTypeIPv4 {
		t.Fatalf("expected IPv4 type, got %d", decoded.Type)
	}
	if decoded.Host != "192.168.1.1" {
		t.Fatalf("expected host 192.168.1.1, got %s", decoded.Host)
	}
	if decoded.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", decoded.Port)
	}
}

func TestAddressIPv6(t *testing.T) {
	addr := &Address{Type: AddressTypeIPv6, Host: "2001:db8::1", Port: 443}
	encoded := addr.Encode()
	if encoded == nil {
		t.Fatal("Encode returned nil")
	}
	if len(encoded) != 19 { // 1 + 16 + 2
		t.Fatalf("expected 19 bytes, got %d", len(encoded))
	}

	decoded, n, err := DecodeAddress(encoded)
	if err != nil {
		t.Fatalf("DecodeAddress error: %v", err)
	}
	if n != 19 {
		t.Fatalf("expected consumed 19, got %d", n)
	}
	if decoded.Type != AddressTypeIPv6 {
		t.Fatalf("expected IPv6 type, got %d", decoded.Type)
	}
	if decoded.Host != "2001:db8::1" {
		t.Fatalf("expected host 2001:db8::1, got %s", decoded.Host)
	}
	if decoded.Port != 443 {
		t.Fatalf("expected port 443, got %d", decoded.Port)
	}
}

func TestAddressDomain(t *testing.T) {
	addr := &Address{Type: AddressTypeDomain, Host: "example.com", Port: 80}
	encoded := addr.Encode()
	if encoded == nil {
		t.Fatal("Encode returned nil")
	}
	// 1 + 1 + len("example.com") + 2 = 15
	if len(encoded) != 15 {
		t.Fatalf("expected 15 bytes, got %d", len(encoded))
	}

	decoded, n, err := DecodeAddress(encoded)
	if err != nil {
		t.Fatalf("DecodeAddress error: %v", err)
	}
	if n != 15 {
		t.Fatalf("expected consumed 15, got %d", n)
	}
	if decoded.Type != AddressTypeDomain {
		t.Fatalf("expected Domain type, got %d", decoded.Type)
	}
	if decoded.Host != "example.com" {
		t.Fatalf("expected host example.com, got %s", decoded.Host)
	}
	if decoded.Port != 80 {
		t.Fatalf("expected port 80, got %d", decoded.Port)
	}
}

func TestAddressDecodeErrors(t *testing.T) {
	// Empty data
	_, _, err := DecodeAddress(nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}

	// Too short for IPv4
	_, _, err = DecodeAddress([]byte{0x01, 1, 2})
	if err == nil {
		t.Fatal("expected error for short IPv4")
	}

	// Too short for IPv6
	_, _, err = DecodeAddress([]byte{0x04, 1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short IPv6")
	}

	// Domain with zero length
	_, _, err = DecodeAddress([]byte{0x03, 0})
	if err == nil {
		t.Fatal("expected error for zero-length domain")
	}

	// Unknown address type
	_, _, err = DecodeAddress([]byte{0xFF, 1, 2, 3})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestAddressEncodeErrors(t *testing.T) {
	// Invalid IPv4
	addr := &Address{Type: AddressTypeIPv4, Host: "not-an-ip", Port: 80}
	if addr.Encode() != nil {
		t.Fatal("expected nil for invalid IPv4")
	}

	// Empty domain
	addr = &Address{Type: AddressTypeDomain, Host: "", Port: 80}
	if addr.Encode() != nil {
		t.Fatal("expected nil for empty domain")
	}

	// Unknown type
	addr = &Address{Type: 0xFF, Host: "test", Port: 80}
	if addr.Encode() != nil {
		t.Fatal("expected nil for unknown type")
	}
}
