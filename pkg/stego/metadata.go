package stego

import (
	"fmt"
	"math"
)

// Info contains metadata extracted from the steganographic image header.
type Info struct {
	Strategy     string
	Channels     int
	BitDepth     int
	IsCompressed bool
	IsEncrypted  bool // NOTE: This is not parsed from the header in the current implementation.
	DataSize     int64
}

// GetInfo inspects the image at the given path and retrieves the steganography metadata.
// Note: DataSize may be incorrect for encrypted images as the length bits are position-scrambled.
// This function assumes that helper functions (loadImage, copyImage, getBitUint8, setBit, makeImageStepper,
// colorToChannels, numBitsAvailable) and the constant HeaderPixels are available within this package.
func GetInfo(imagePath string) (*Info, error) {
	imgRaw, err := loadImage(imagePath)
	if err != nil {
		return nil, err
	}
	img := copyImage(imgRaw)
	pixels := img.Pix
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	if width*height < HeaderPixels {
		return nil, fmt.Errorf("image too small to contain header")
	}

	// 1. Parse Bits Per Channel (Pixel 0)
	var bitsPerChannel int
	channels0 := pixels[0:4]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels0[i], 0) != 0 {
			bitsPerChannel = setBit(bitsPerChannel, i)
		}
	}

	// 2. Parse Num Channels (Pixel 1)
	var numChannels int
	channels1 := pixels[4:8]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels1[i], 0) != 0 {
			numChannels = setBit(numChannels, i)
		}
	}

	// 3. Parse Strategy & Compression (Pixel 2)
	var strategyID int
	channels2 := pixels[8:12]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels2[i], 0) != 0 {
			strategyID = setBit(strategyID, i)
		}
	}

	isCompressed := (strategyID & 4) != 0
	strategyID = strategyID & 3 // Strip compression bit

	strategy := "lsb"
	switch strategyID {
	case 1:
		strategy = "lsb-matching"
	case 2:
		strategy = "dct"
	}

	// 4. Read Data Size (Length)
	// We assume seed 0 (no passphrase). If a passphrase was used, this will read garbage.
	stepperSeed := int64(0)
	stepper, err := makeImageStepper(bitsPerChannel, width, height, numChannels, stepperSeed, "lsb")
	if err != nil {
		return nil, err
	}

	// Skip Header (35 pixels)
	for i := 0; i < HeaderPixels; i++ {
		stepper.skipPixel()
	}

	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	numBitsToEncodeNumMessageBits := int(math.Ceil(math.Log2(float64(totalBitsInImage))))
	var numMessageBits int64

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		chans := colorToChannels(img.At(stepper.x, stepper.y))
		val := chans[stepper.channel]
		if getBitUint8(val, stepper.bitIndexOffset) != 0 {
			numMessageBits = int64(setBit(int(numMessageBits), i))
		}
		stepper.step()
	}

	return &Info{
		Strategy:     strategy,
		Channels:     numChannels,
		BitDepth:     bitsPerChannel,
		IsCompressed: isCompressed,
		IsEncrypted:  false, // Header format does not currently store encryption status
		DataSize:     numMessageBits / 8, // Convert bits to bytes
	}, nil
}