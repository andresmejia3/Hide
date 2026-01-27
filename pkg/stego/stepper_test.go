package stego

import "testing"

func TestImageStepper(t *testing.T) {
	// Setup a stepper for a 2x2 image, 3 channels (RGB), 1 bit per channel
	// Total capacity: 2 * 2 * 3 * 1 = 12 bits
	width := 2
	height := 2
	channels := 3
	bitsPerChannel := 1

	stepper, err := makeImageStepper(bitsPerChannel, width, height, channels, 0, "lsb")
	if err != nil {
		t.Fatalf("Failed to create stepper: %v", err)
	}

	if stepper.x != 0 || stepper.y != 0 || stepper.channel != 0 {
		t.Errorf("Initial state incorrect: %+v", stepper)
	}

	// Should move to next channel (0 -> 1) because bitsPerChannel is 1
	stepper.step()
	if stepper.channel != 1 || stepper.x != 0 {
		t.Errorf("Step 1 failed: %+v", stepper)
	}

	stepper.step()
	if stepper.channel != 2 {
		t.Errorf("Step 2 failed: %+v", stepper)
	}

	// Move to next pixel (channel 2 -> channel 0, x 0 -> 1)
	stepper.step()
	if stepper.channel != 0 || stepper.x != 1 || stepper.y != 0 {
		t.Errorf("Step 3 (pixel change) failed: %+v", stepper)
	}

	// Fast forward to end of first row (width is 2, so x=0, x=1 are valid)
	// We are currently at x=1, ch=0.
	// Need to step ch0->ch1, ch1->ch2, ch2->next_row
	stepper.step() // x=1, ch=1
	stepper.step() // x=1, ch=2
	stepper.step() // Should move to y=1, x=0, ch=0

	if stepper.y != 1 || stepper.x != 0 {
		t.Errorf("Row change failed: %+v", stepper)
	}
}

func TestImageStepperOverflow(t *testing.T) {
	// 2x1 image, 1 channel, 1 bit per channel. Capacity = 2 bits.
	stepper, err := makeImageStepper(1, 2, 1, 1, 0, "lsb")
	if err != nil {
		t.Fatalf("Failed to create stepper: %v", err)
	}

	if err := stepper.step(); err != nil {
		t.Errorf("First step should succeed")
	}

	// Step again (should fail because we ran out of pixels)
	if err := stepper.step(); err == nil {
		t.Error("Expected error when stepping past image bounds, got nil")
	}
}

func TestRandomIteratorCoverage(t *testing.T) {
	// 10x10 image = 100 pixels.
	// Random iterator skips first HeaderPixels.
	// Should yield 65 unique coordinates.
	width, height := 10, 10
	seed := int64(12345)
	it := newRandomIterator(width, height, seed)

	visited := make(map[int]bool)
	count := 0

	for {
		x, y, ok := it.next()
		if !ok {
			break
		}
		idx := y*width + x
		if visited[idx] {
			t.Errorf("Random iterator visited pixel (%d,%d) twice", x, y)
		}
		visited[idx] = true
		count++
	}

	expected := (width * height) - HeaderPixels
	if count != expected {
		t.Errorf("Random iterator visited %d pixels, want %d", count, expected)
	}
}

func TestDCTIteratorBounds(t *testing.T) {
	// 16x16 image.
	// Blocks are 8x8.
	// Width in blocks = 2.
	// Height in blocks = 2.
	// DCT iterator skips the first row of blocks (y=0).
	// So it should visit (0,1) and (1,1).
	width, height := 16, 16
	it := newDctIterator(width, height)

	// Block 1: (0, 1)
	x, y, ok := it.next()
	if !ok {
		t.Fatal("DCT iterator finished too early (step 1)")
	}
	if x != 0 || y != 1 {
		t.Errorf("DCT iterator step 1: got (%d,%d), want (0,1)", x, y)
	}

	// Block 2: (1, 1)
	x, y, ok = it.next()
	if !ok {
		t.Fatal("DCT iterator finished too early (step 2)")
	}
	if x != 1 || y != 1 {
		t.Errorf("DCT iterator step 2: got (%d,%d), want (1,1)", x, y)
	}

	// Should be done
	_, _, ok = it.next()
	if ok {
		t.Error("DCT iterator should be exhausted but returned true")
	}
}
