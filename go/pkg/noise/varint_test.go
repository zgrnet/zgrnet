package noise

import (
	"math"
	"math/rand"
	"testing"
)

func TestVarint_Zero(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], 0)
	if n != 1 {
		t.Fatalf("EncodeVarint(0) wrote %d bytes, want 1", n)
	}
	if buf[0] != 0 {
		t.Fatalf("EncodeVarint(0) = 0x%02x, want 0x00", buf[0])
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 0 || consumed != 1 {
		t.Fatalf("DecodeVarint = (%d, %d), want (0, 1)", v, consumed)
	}
}

func TestVarint_OneByte_127(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], 127)
	if n != 1 {
		t.Fatalf("EncodeVarint(127) wrote %d bytes, want 1", n)
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 127 || consumed != 1 {
		t.Fatalf("DecodeVarint = (%d, %d), want (127, 1)", v, consumed)
	}
}

func TestVarint_TwoByte_128(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], 128)
	if n != 2 {
		t.Fatalf("EncodeVarint(128) wrote %d bytes, want 2", n)
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 128 || consumed != 2 {
		t.Fatalf("DecodeVarint = (%d, %d), want (128, 2)", v, consumed)
	}
}

func TestVarint_TwoByte_16383(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], 16383)
	if n != 2 {
		t.Fatalf("EncodeVarint(16383) wrote %d bytes, want 2", n)
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 16383 || consumed != 2 {
		t.Fatalf("DecodeVarint = (%d, %d), want (16383, 2)", v, consumed)
	}
}

func TestVarint_ThreeByte(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], 16384)
	if n != 3 {
		t.Fatalf("EncodeVarint(16384) wrote %d bytes, want 3", n)
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 16384 || consumed != 3 {
		t.Fatalf("DecodeVarint = (%d, %d), want (16384, 3)", v, consumed)
	}
}

func TestVarint_MaxUint64(t *testing.T) {
	var buf [MaxVarintLen]byte
	n := EncodeVarint(buf[:], math.MaxUint64)
	if n != 10 {
		t.Fatalf("EncodeVarint(MaxUint64) wrote %d bytes, want 10", n)
	}
	v, consumed, err := DecodeVarint(buf[:n])
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != math.MaxUint64 || consumed != 10 {
		t.Fatalf("DecodeVarint = (%d, %d), want (%d, 10)", v, consumed, uint64(math.MaxUint64))
	}
}

func TestVarint_EmptyBuf(t *testing.T) {
	_, _, err := DecodeVarint([]byte{})
	if err != ErrVarintTruncated {
		t.Fatalf("DecodeVarint(empty) error = %v, want ErrVarintTruncated", err)
	}
}

func TestVarint_TruncatedBuf(t *testing.T) {
	_, _, err := DecodeVarint([]byte{0x80})
	if err != ErrVarintTruncated {
		t.Fatalf("DecodeVarint(truncated) error = %v, want ErrVarintTruncated", err)
	}

	_, _, err = DecodeVarint([]byte{0x80, 0x80})
	if err != ErrVarintTruncated {
		t.Fatalf("DecodeVarint(truncated 2) error = %v, want ErrVarintTruncated", err)
	}
}

func TestVarint_RoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	var buf [MaxVarintLen]byte

	for i := 0; i < 1000; i++ {
		original := rng.Uint64()
		n := EncodeVarint(buf[:], original)
		decoded, consumed, err := DecodeVarint(buf[:n])
		if err != nil {
			t.Fatalf("iteration %d: DecodeVarint error: %v (value=%d)", i, err, original)
		}
		if decoded != original {
			t.Fatalf("iteration %d: roundtrip mismatch: got %d, want %d", i, decoded, original)
		}
		if consumed != n {
			t.Fatalf("iteration %d: consumed %d bytes, encoded %d", i, consumed, n)
		}
	}
}

func TestVarint_AppendVarint(t *testing.T) {
	var buf [MaxVarintLen]byte

	tests := []uint64{0, 1, 127, 128, 16383, 16384, math.MaxUint64}
	for _, v := range tests {
		appended := AppendVarint(nil, v)
		n := EncodeVarint(buf[:], v)
		if len(appended) != n {
			t.Fatalf("AppendVarint(%d) len=%d, EncodeVarint len=%d", v, len(appended), n)
		}
		for i := range appended {
			if appended[i] != buf[i] {
				t.Fatalf("AppendVarint(%d) byte %d: got 0x%02x, want 0x%02x", v, i, appended[i], buf[i])
			}
		}
	}
}

func TestVarintLen(t *testing.T) {
	tests := []struct {
		v    uint64
		want int
	}{
		{0, 1},
		{127, 1},
		{128, 2},
		{16383, 2},
		{16384, 3},
		{math.MaxUint64, 10},
	}
	for _, tt := range tests {
		got := VarintLen(tt.v)
		if got != tt.want {
			t.Errorf("VarintLen(%d) = %d, want %d", tt.v, got, tt.want)
		}
	}
}

func TestVarint_DecodeWithTrailingData(t *testing.T) {
	buf := []byte{0x80, 0x01, 0xFF, 0xFF}
	v, consumed, err := DecodeVarint(buf)
	if err != nil {
		t.Fatalf("DecodeVarint error: %v", err)
	}
	if v != 128 || consumed != 2 {
		t.Fatalf("DecodeVarint = (%d, %d), want (128, 2)", v, consumed)
	}
}
