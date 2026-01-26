package stego

import "testing"

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
