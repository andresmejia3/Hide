package stego

import (
	"errors"
	"fmt"
	"image"
	"image/png"
	"math"
	"os"

	"github.com/rs/zerolog/log"
)

type ConcealArgs struct {
	ImagePath         *string
	Passphrase        *string
	PublicKeyPath     *string
	Message           *string
	Output            *string
	NumBitsPerChannel *int
	Encoding          *string
	NumChannels       *int
	Verbose           *bool
	Strategy          *string
}

type RevealArgs struct {
	ImagePath      *string
	Passphrase     *string
	PrivateKeyPath *string
	Encoding       *string
	Verbose        *bool
	Strategy       *string
}

func Conceal(args *ConcealArgs) error {
	img, err := loadImage(*args.ImagePath)

	if err != nil {
		return err
	}

	if *args.Output == "" {
		*args.Output = fmt.Sprintf("%s.out", *args.ImagePath)
	}

	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	messageBytes := []byte(*args.Message)

	var seed int64
	if *args.Passphrase != "" {
		messageBytes, err = encrypt(messageBytes, *args.Passphrase)
		if err != nil {
			return err
		}
		seed = getSeed(*args.Passphrase)
	}

	// DCT Strategy requires a Linear header to avoid collision with blocks.
	// We force the stepper to be linear (seed 0) for the header writing phase.
	stepperSeed := seed
	if *args.Strategy == "dct" {
		stepperSeed = 0
		// Force header values to be consistent with DCT strategy
		// DCT effectively uses 1 channel (Blue) and custom encoding.
		// We set these to 1 to avoid misleading metadata in the header.
		one := 1
		args.NumChannels = &one
		args.NumBitsPerChannel = &one
	}

	if *args.PublicKeyPath != "" {
		messageBytes, err = encryptRSA(messageBytes, *args.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("RSA encryption failed: %v", err)
		}
	}

	totalBitsToBeWritten := len(messageBytes) * 8
	stepper := makeImageStepper(*args.NumBitsPerChannel, width, height, *args.NumChannels, totalBitsToBeWritten, stepperSeed)
	outputImage := copyImage(img)
	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	pixels := outputImage.Pix

	numBitsToEncodeNumMessageBits := int(math.Floor(math.Log2(float64(totalBitsInImage))))
	totalBitsAvailable := numBitsAvailable(width, height, *args.NumChannels, *args.NumBitsPerChannel)

	if *args.Verbose {
		log.Debug().Int("width", width).Int("height", height).Msg("Image dimensions")
		log.Debug().Int("bits", totalBitsInImage).Msg("Total bits in image")
		log.Debug().Int("available", totalBitsAvailable).Msg("Total bits available for use")
		log.Debug().Int("required", totalBitsToBeWritten).Msg("Total bits to be written")
	}

	if width*height < 3 {
		return errors.New("image must have at least 3 pixels")
	}

	// Capacity check depends on strategy
	capacity := totalBitsAvailable
	if *args.Strategy == "dct" {
		// 1 bit per 8x8 block
		// We skip the first row of blocks (blockY=0) to reserve space for the header
		capacity = (width / 8) * ((height / 8) - 1)
	}
	if capacity < totalBitsToBeWritten {
		return errors.New("image is not large enough to hide a message")
	}

	for i := 0; i < 4; i++ {
		if getBit(*args.NumBitsPerChannel, i) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.Verbose {
		log.Debug().Msg("Encoded number of bits per channel into the first pixel")
	}

	stepper.skipPixel()

	for i := 4; i < 8; i++ {
		if getBit(*args.NumChannels, i-4) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.Verbose {
		log.Debug().Msg("Encoded number of channels into the second pixel")
	}

	stepper.skipPixel()

	// Encode Strategy ID into the third pixel
	// 0: lsb, 1: lsb-matching, 2: dct
	strategyID := 0
	switch *args.Strategy {
	case "lsb-matching":
		strategyID = 1
	case "dct":
		strategyID = 2
	}

	for i := 8; i < 12; i++ {
		if getBit(strategyID, i-8) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}
	stepper.skipPixel()

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		pixel := getPixel(outputImage, stepper.x, stepper.y)
		channelValue := pixel[stepper.channel]

		if getBit(totalBitsToBeWritten, i) == 0 {
			pixel[stepper.channel] = clearBitUint8(channelValue, stepper.bitIndexOffset)
		} else {
			pixel[stepper.channel] = setBitUint8(channelValue, stepper.bitIndexOffset)
		}

		if err := stepper.step(); err != nil {
			return err
		}
	}

	if *args.Verbose {
		log.Debug().Msg("Encoded the number of bits that will be written")
	}

	if *args.Strategy == "dct" {
		// DCT Strategy: Embed in 8x8 blocks
		// Skip the first row of blocks to protect metadata (header) completely
		blockX := 0
		blockY := 1
		blocksW := width / 8

		for _, encryptedByte := range messageBytes {
			for i := 0; i < 8; i++ {
				if blockX >= blocksW {
					blockX = 0
					blockY++
				}
				if blockY*8+8 > height {
					return errors.New("image too small for DCT message")
				}

				// Extract Blue channel 8x8 block
				var block [8][8]float64
				baseX, baseY := blockX*8, blockY*8
				for bx := 0; bx < 8; bx++ {
					for by := 0; by < 8; by++ {
						pix := getPixel(outputImage, baseX+bx, baseY+by)
						block[bx][by] = float64(pix[2]) // Blue channel
					}
				}

				// DCT
				dctBlock := dct2d(block)

				// Embed bit in (4,4) coefficient
				// Use a scaling factor to make the embedding robust against float->uint8 conversion noise
				const dctScale = 10.0
				bit := getBitUint8(encryptedByte, i)
				val := dctBlock[4][4]
				q := int(math.Round(val / dctScale))

				// Ensure q % 2 matches the bit
				if (q%2+2)%2 != bit {
					if val < float64(q)*dctScale {
						q--
					} else {
						q++
					}
				}
				dctBlock[4][4] = float64(q) * dctScale

				// IDCT
				idctBlock := idct2d(dctBlock)

				// Write back
				for bx := 0; bx < 8; bx++ {
					for by := 0; by < 8; by++ {
						pix := getPixel(outputImage, baseX+bx, baseY+by)
						pix[2] = uint8(math.Max(0, math.Min(255, idctBlock[bx][by])))
					}
				}
				blockX++
			}
		}
	} else {
		// LSB or LSB Matching
		useMatching := *args.Strategy == "lsb-matching"
		if err := concealBodyLSB(outputImage, stepper, messageBytes, useMatching); err != nil {
			return err
		}
	}

	file, err := os.Create(*args.Output)
	if err != nil {
		return err
	}

	err = png.Encode(file, outputImage)
	if err != nil {
		return err
	}

	if *args.Verbose {
		log.Info().Str("output", *args.Output).Msg("Encoded message into the image")
	}

	return nil
}

func concealBodyLSB(img *image.NRGBA, stepper *ImageStepper, message []byte, matching bool) error {
	for _, b := range message {
		for i := 0; i < 8; i++ {
			pixel := getPixel(img, stepper.x, stepper.y)
			channelValue := pixel[stepper.channel]
			bit := getBitUint8(b, i)

			if matching {
				pixel[stepper.channel] = matchBitUint8(channelValue, stepper.bitIndexOffset, bit)
			} else {
				if bit == 0 {
					pixel[stepper.channel] = clearBitUint8(channelValue, stepper.bitIndexOffset)
				} else {
					pixel[stepper.channel] = setBitUint8(channelValue, stepper.bitIndexOffset)
				}
			}
			if err := stepper.step(); err != nil {
				return err
			}
		}
	}

	return nil
}

func Reveal(args *RevealArgs) error {
	imgRaw, err := loadImage(*args.ImagePath)
	if err != nil {
		return err
	}
	// Convert to NRGBA to ensure consistent pixel access and avoid type assertion panics
	img := copyImage(imgRaw)

	var channels []uint8
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y
	numBitsToUsePerChannel := 0
	numChannels := 0
	numMessageBits := 0

	channels = colorToChannels(img.At(0, 0))

	for i := 0; i < 4; i++ {
		channelValue := channels[i]

		if getBitUint8(channelValue, 0) == 0 {
			numBitsToUsePerChannel = clearBit(numBitsToUsePerChannel, i)
		} else {
			numBitsToUsePerChannel = setBit(numBitsToUsePerChannel, i)
		}
	}

	if *args.Verbose {
		log.Debug().Int("width", width).Int("height", height).Msg("Image dimensions")
		log.Debug().Int("bitsPerChannel", numBitsToUsePerChannel).Msg("Decoded number of bits to use per channel")
	}

	if (image.Point{X: 1, Y: 0}.In(img.Bounds())) {
		channels = colorToChannels(img.At(1, 0))
	} else {
		channels = colorToChannels(img.At(0, 1))
	}

	for i := 0; i < 4; i++ {
		channelValue := channels[i]

		if getBitUint8(channelValue, 0) == 0 {
			numChannels = clearBit(numChannels, i)
		} else {
			numChannels = setBit(numChannels, i)
		}
	}

	// Decode Strategy ID from the third pixel
	var p2x, p2y int
	if width >= 3 {
		p2x, p2y = 2, 0
	} else if width == 2 {
		p2x, p2y = 0, 1
	} else {
		p2x, p2y = 0, 2
	}
	channels = colorToChannels(img.At(p2x, p2y))
	strategyID := 0
	for i := 0; i < 4; i++ {
		if getBitUint8(channels[i], 0) != 0 {
			strategyID = setBit(strategyID, i)
		}
	}

	// Auto-detect strategy
	switch strategyID {
	case 0:
		*args.Strategy = "lsb"
	case 1:
		*args.Strategy = "lsb-matching"
	case 2:
		*args.Strategy = "dct"
	}
	// If strategyID is unknown, we default to whatever was passed in args or standard lsb, but here we trust the file.

	// Validate header data to prevent panics on non-stego images
	if numChannels < 1 || numChannels > 4 {
		return fmt.Errorf("invalid header: detected %d channels (must be 1-4)", numChannels)
	}
	if numBitsToUsePerChannel < 1 || numBitsToUsePerChannel > 8 {
		return fmt.Errorf("invalid header: detected %d bits per channel (must be 1-8)", numBitsToUsePerChannel)
	}

	if *args.Verbose {
		log.Debug().Int("channels", numChannels).Msg("Decoded number of channels")
	}

	var seed int64
	if *args.Passphrase != "" {
		seed = getSeed(*args.Passphrase)
	}

	stepperSeed := seed
	if *args.Strategy == "dct" {
		stepperSeed = 0
	}
	stepper := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, numMessageBits, stepperSeed)
	stepper.skipPixel()
	stepper.skipPixel()
	stepper.skipPixel()

	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	numBitsToEncodeNumMessageBits := int(math.Floor(math.Log2(float64(totalBitsInImage))))

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		channels := colorToChannels(img.At(stepper.x, stepper.y))
		channelValue := channels[stepper.channel]

		if getBitUint8(channelValue, stepper.bitIndexOffset) == 0 {
			numMessageBits = clearBit(numMessageBits, i)
		} else {
			numMessageBits = setBit(numMessageBits, i)
		}

		if err := stepper.step(); err != nil {
			return err
		}
	}

	// Validate message length against capacity
	var capacity int
	if *args.Strategy == "dct" {
		capacity = (width / 8) * ((height / 8) - 1)
	} else {
		// LSB capacity (approximate check, stepper handles exact bounds)
		capacity = numBitsAvailable(width, height, numChannels, numBitsToUsePerChannel)
	}
	if numMessageBits < 0 || numMessageBits > capacity {
		return fmt.Errorf("invalid header: message length %d exceeds capacity %d", numMessageBits, capacity)
	}

	if *args.Verbose {
		log.Debug().Int("messageBits", numMessageBits).Msg("Decoded number of bits used to encode the message")
	}

	messageBytes := make([]byte, numMessageBits/8)
	numBitsRead := 0
	byteIndex := 0

	if *args.Strategy == "dct" {
		blockX := 0
		blockY := 1
		blocksW := width / 8

		for i := 0; i < numMessageBits; i++ {
			if blockX >= blocksW {
				blockX = 0
				blockY++
			}
			if blockY*8+8 > height {
				return errors.New("image too small for DCT message")
			}

			// Extract Blue channel 8x8 block
			var block [8][8]float64
			baseX, baseY := blockX*8, blockY*8
			for bx := 0; bx < 8; bx++ {
				for by := 0; by < 8; by++ {
					pix := getPixel(img, baseX+bx, baseY+by)
					block[bx][by] = float64(pix[2])
				}
			}

			// DCT
			dctBlock := dct2d(block)
			const dctScale = 10.0
			q := int(math.Round(dctBlock[4][4] / dctScale))

			if (q%2+2)%2 != 0 {
				messageBytes[byteIndex] = setBitUint8(messageBytes[byteIndex], numBitsRead)
			} else {
				messageBytes[byteIndex] = clearBitUint8(messageBytes[byteIndex], numBitsRead)
			}

			if numBitsRead++; numBitsRead == 8 {
				numBitsRead = 0
				byteIndex++
			}
			blockX++
		}
	} else {
		// LSB or LSB Matching (decoding is same for both)
		for i := 0; i < numMessageBits; i++ {
			channels := colorToChannels(img.At(stepper.x, stepper.y))
			channelValue := channels[stepper.channel]

			if getBitUint8(channelValue, stepper.bitIndexOffset) == 0 {
				messageBytes[byteIndex] = clearBitUint8(messageBytes[byteIndex], numBitsRead)
			} else {
				messageBytes[byteIndex] = setBitUint8(messageBytes[byteIndex], numBitsRead)
			}

			if numBitsRead++; numBitsRead == 8 {
				numBitsRead = 0
				byteIndex++
			}

			if err := stepper.step(); err != nil {
				return err
			}
		}
	}

	var message string

	if *args.Passphrase != "" {
		decrypted, err := decrypt(messageBytes, *args.Passphrase)
		if err != nil {
			return fmt.Errorf("failed to decrypt message: %v", err)
		}
		message = string(decrypted)

	} else if *args.PrivateKeyPath != "" {
		decryptedBytes, err := decryptRSA(messageBytes, *args.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("RSA decryption failed: %v", err)
		}
		message = string(decryptedBytes)

	} else {
		message = string(messageBytes)
	}

	fmt.Println(message)
	return nil
}
