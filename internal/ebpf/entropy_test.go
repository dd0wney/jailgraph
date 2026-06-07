package ebpf

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	uniform := make([]byte, 256) // every byte value once → max entropy 8.0
	for i := range uniform {
		uniform[i] = byte(i)
	}
	allSame := make([]byte, 256) // one symbol → 0.0
	twoEqual := make([]byte, 256)
	for i := range twoEqual {
		twoEqual[i] = byte(i%2) * 0xFF // 0x00 / 0xFF, 50/50 → 1.0 bit/byte
	}

	cases := []struct {
		name string
		data []byte
		want float64
	}{
		{"empty", nil, 0},
		{"single-symbol", allSame, 0},
		{"two-equal-symbols", twoEqual, 1.0},
		{"uniform-256", uniform, 8.0},
	}
	for _, c := range cases {
		got := shannonEntropy(c.data)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("shannonEntropy(%s) = %.6f, want %.6f", c.name, got, c.want)
		}
	}
}

func TestShannonEntropy_EncryptedVsPlaintext(t *testing.T) {
	// Plaintext-ish: a small alphabet (low entropy). Encrypted/compressed-ish:
	// a wide, even byte spread (high entropy). The detector relies on this gap.
	plain := []byte("aaaabbbbccccddddaaaabbbbccccdddd") // 4 symbols → 2.0 bits/byte
	if h := shannonEntropy(plain); h > 3.0 {
		t.Errorf("plaintext entropy = %.3f, expected low (<3)", h)
	}
	highEntropy := make([]byte, 1024)
	for i := range highEntropy {
		highEntropy[i] = byte((i*167 + 13) % 256) // even spread across all 256
	}
	if h := shannonEntropy(highEntropy); h < 7.5 {
		t.Errorf("high-entropy sample = %.3f, expected near-max (>7.5)", h)
	}
}
