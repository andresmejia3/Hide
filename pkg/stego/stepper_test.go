package stego

import "testing"

func TestImageStepper(t *testing.T) {
	// Setup a stepper for a 2x2 image, 3 channels (RGB), 1 bit per channel
	// Total capacity: 2 * 2 * 3 * 1 = 12 bits
	width := 2
	height := 2
	channels := 3
	bitsPerChannel := 1
	totalBits := 12

	stepper := makeImageStepper(bitsPerChannel, width, height, channels, totalBits)

	// Test Initial State
	if stepper.x != 0 || stepper.y != 0 || stepper.channel != 0 {
		t.Errorf("Initial state incorrect: %+v", stepper)
	}

	// Step 1: Should move to next channel (0 -> 1) because bitsPerChannel is 1
	stepper.step()
	if stepper.channel != 1 || stepper.x != 0 {
		t.Errorf("Step 1 failed: %+v", stepper)
	}

	// Step 2: Move to channel 2
	stepper.step()
	if stepper.channel != 2 {
		t.Errorf("Step 2 failed: %+v", stepper)
	}

	// Step 3: Move to next pixel (channel 2 -> channel 0, x 0 -> 1)
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
	stepper := makeImageStepper(1, 2, 1, 1, 10) // Trying to write 10 bits

	// Step once (ok)
	if err := stepper.step(); err != nil {
		t.Errorf("First step should succeed")
	}

	// Step again (should fail because we ran out of pixels)
	if err := stepper.step(); err == nil {
		t.Error("Expected error when stepping past image bounds, got nil")
	}
}
