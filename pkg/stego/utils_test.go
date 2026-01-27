package stego

import (
	"math"
	"testing"
)

func TestBitManipulation(t *testing.T) {
	// 0000 0000 | (1<<2) = 0000 0100 (4)
	if got := setBit(0, 2); got != 4 {
		t.Errorf("setBit(0, 2) = %d; want 4", got)
	}

	// 0000 0100 & ^(1<<2) = 0000 0000 (0)
	if got := clearBit(4, 2); got != 0 {
		t.Errorf("clearBit(4, 2) = %d; want 0", got)
	}

	if got := getBit(4, 2); got != 1 {
		t.Errorf("getBit(4, 2) = %d; want 1", got)
	}
	if got := getBit(4, 0); got != 0 {
		t.Errorf("getBit(4, 0) = %d; want 0", got)
	}
}

func TestUint8BitManipulation(t *testing.T) {
	if got := setBitUint8(0, 2); got != 4 {
		t.Errorf("setBitUint8(0, 2) = %d; want 4", got)
	}

	if got := clearBitUint8(4, 2); got != 0 {
		t.Errorf("clearBitUint8(4, 2) = %d; want 0", got)
	}

	if got := getBitUint8(4, 2); got != 1 {
		t.Errorf("getBitUint8(4, 2) = %d; want 1", got)
	}
}

func TestDCTRoundTrip(t *testing.T) {
	// Create a test 8x8 block with some gradient data
	var block [8][8]float64
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			block[i][j] = float64((i + j) * 10)
		}
	}

	dct := dct2d(block)
	idct := idct2d(dct)

	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if math.Abs(block[i][j]-idct[i][j]) > 0.0001 {
				t.Errorf("DCT round trip mismatch at %d,%d: got %f, want %f", i, j, idct[i][j], block[i][j])
			}
		}
	}
}
