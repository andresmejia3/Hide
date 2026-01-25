package stego

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"os"

	"github.com/klauspost/reedsolomon"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

type ConcealArgs struct {
	ImagePath         *string
	Passphrase        *string
	PublicKeyPath     *string
	Message           *string
	File              *string
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
	Output         *string
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

	var messageBytes []byte
	if args.File != nil && *args.File != "" {
		var err error
		messageBytes, err = os.ReadFile(*args.File)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}
	} else {
		messageBytes = []byte(*args.Message)
	}

	var seed int64
	// Generate random salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	if *args.Passphrase != "" {
		messageBytes, err = encrypt(messageBytes, *args.Passphrase, salt)
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

	// Apply Reed-Solomon Error Correction
	messageBytes, err = addReedSolomon(messageBytes)
	if err != nil {
		return fmt.Errorf("failed to apply Reed-Solomon encoding: %v", err)
	}

	totalBitsToBeWritten := len(messageBytes) * 8
	stepper := makeImageStepper(*args.NumBitsPerChannel, width, height, *args.NumChannels, totalBitsToBeWritten+numBitsToEncodeNumMessageBits, stepperSeed)
	outputImage := copyImage(img)
	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	pixels := outputImage.Pix

	numBitsToEncodeNumMessageBits := int(math.Ceil(math.Log2(float64(totalBitsInImage))))
	totalBitsAvailable := numBitsAvailable(width, height, *args.NumChannels, *args.NumBitsPerChannel)

	if *args.Verbose {
		log.Debug().Int("width", width).Int("height", height).Msg("Image dimensions")
		log.Debug().Int("bits", totalBitsInImage).Msg("Total bits in image")
		log.Debug().Int("available", totalBitsAvailable).Msg("Total bits available for use")
		log.Debug().Int("required", totalBitsToBeWritten).Msg("Total bits to be written")
	}

	if width*height < 35 {
		return errors.New("image must have at least 35 pixels (header+salt)")
	}

	// Capacity check depends on strategy
	capacity := totalBitsAvailable
	if *args.Strategy == "dct" {
		// 1 bit per 8x8 block
		if width < 9 {
			return errors.New("image width must be at least 9 pixels for DCT strategy to fit header")
		}
		// We skip the first row of blocks (blockY=0) to reserve space for the header
		capacity = (width / 8) * ((height / 8) - 1)
	} else {
		// Subtract reserved pixels (35 pixels * channels * bitsPerChannel)
		capacity -= 35 * *args.NumChannels * *args.NumBitsPerChannel
	}

	required := totalBitsToBeWritten
	if *args.Strategy != "dct" {
		required += numBitsToEncodeNumMessageBits
	}
	if capacity < required {
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

	// Encode Salt into pixels 3..34 (32 pixels * 4 channels * 1 bit = 128 bits = 16 bytes)
	// We use 1 bit per channel regardless of args to ensure robustness of salt
	saltBitIndex := 0
	for i := 12; i < 12+(32*4); i++ {
		bit := getBitUint8(salt[saltBitIndex/8], saltBitIndex%8)
		if bit == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
		saltBitIndex++
		if i%4 == 3 {
			stepper.skipPixel()
		} // Advance stepper every 4 channels (1 pixel)
	}

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

	bar := progressbar.NewOptions64(
		int64(len(messageBytes)),
		progressbar.OptionSetDescription("encoding"),
		progressbar.OptionSetWriter(os.Stderr),
	)

	if *args.Strategy == "dct" {
		// DCT Strategy: Embed in 8x8 blocks
		// Skip the first row of blocks to protect metadata (header) completely
		blockX := 0
		blockY := 1
		blocksW := width / 8

		for _, encryptedByte := range messageBytes {
			bar.Add(1)
			for i := 0; i < 8; i++ {
				if blockX >= blocksW {
					blockX = 0
					blockY++
				}
				if blockY*8+8 > height {
					return errors.New("image too small for DCT message")
				}

				bit := getBitUint8(encryptedByte, i)
				embedDCTBlock(outputImage, blockX, blockY, bit)
				blockX++
			}
		}
	} else {
		// LSB or LSB Matching
		useMatching := *args.Strategy == "lsb-matching"
		if err := concealBodyLSB(outputImage, stepper, messageBytes, useMatching, bar); err != nil {
			return err
		}
	}

	file, err := os.Create(*args.Output)
	if err != nil {
		return err
	}
	defer file.Close()

	err = png.Encode(file, outputImage)
	if err != nil {
		return err
	}

	if *args.Verbose {
		log.Info().Str("output", *args.Output).Msg("Encoded message into the image")
	}

	return nil
}

func concealBodyLSB(img *image.NRGBA, stepper *ImageStepper, message []byte, matching bool, bar *progressbar.ProgressBar) error {
	var rng io.ByteReader
	if matching {
		rng = bufio.NewReader(rand.Reader)
	}

	for _, b := range message {
		bar.Add(1)
		for i := 0; i < 8; i++ {
			pixel := getPixel(img, stepper.x, stepper.y)
			channelValue := pixel[stepper.channel]
			bit := getBitUint8(b, i)

			if matching {
				val, err := matchBitUint8(channelValue, stepper.bitIndexOffset, bit, rng)
				if err != nil {
					return err
				}
				pixel[stepper.channel] = val
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
	pixels := img.Pix

	var channels []uint8
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y
	numBitsToUsePerChannel := 0

	if width*height < 35 {
		return errors.New("image must have at least 35 pixels (header+salt)")
	}
	numChannels := 0
	numMessageBits := 0

	channels = pixels[0:4]

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

	channels = pixels[4:8]

	for i := 0; i < 4; i++ {
		channelValue := channels[i]

		if getBitUint8(channelValue, 0) == 0 {
			numChannels = clearBit(numChannels, i)
		} else {
			numChannels = setBit(numChannels, i)
		}
	}

	// Decode Strategy ID from the third pixel
	channels = pixels[8:12]
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

	// Decode Salt from pixels 3..34
	salt := make([]byte, 16)
	saltBitIndex := 0
	for i := 12; i < 12+(32*4); i++ {
		if getBitUint8(pixels[i], 0) != 0 {
			salt[saltBitIndex/8] = setBitUint8(salt[saltBitIndex/8], saltBitIndex%8)
		}
		saltBitIndex++
	}

	var seed int64
	if *args.Passphrase != "" {
		seed = getSeed(*args.Passphrase)
	}

	stepperSeed := seed
	if *args.Strategy == "dct" {
		stepperSeed = 0
	}
	// Initialize with total bits in image to ensure bounds check works while reading header
	stepper := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, numBitsAvailable(width, height, 4, 8), stepperSeed)
	stepper.skipPixel()
	stepper.skipPixel()
	stepper.skipPixel()
	// Skip salt pixels
	for i := 0; i < 32; i++ {
		stepper.skipPixel()
	}

	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	numBitsToEncodeNumMessageBits := int(math.Ceil(math.Log2(float64(totalBitsInImage))))

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
		if width < 9 {
			return errors.New("image width must be at least 9 pixels for DCT strategy to fit header")
		}
		capacity = (width / 8) * ((height / 8) - 1)
	} else {
		// LSB capacity (approximate check, stepper handles exact bounds)
		capacity = numBitsAvailable(width, height, numChannels, numBitsToUsePerChannel)
		capacity -= 35 * numChannels * numBitsToUsePerChannel
		// Account for the bits used to store the message length
		capacity -= int(math.Ceil(math.Log2(float64(numBitsAvailable(width, height, 4, 8)))))
	}

	if numMessageBits < 0 || numMessageBits > capacity {
		return fmt.Errorf("invalid header: message length %d exceeds capacity %d", numMessageBits, capacity)
	}
	if numMessageBits%8 != 0 {
		return fmt.Errorf("invalid header: message length %d is not a multiple of 8", numMessageBits)
	}

	if *args.Verbose {
		log.Debug().Int("messageBits", numMessageBits).Msg("Decoded number of bits used to encode the message")
	}

	messageBytes := make([]byte, numMessageBits/8)
	numBitsRead := 0
	byteIndex := 0

	bar := progressbar.NewOptions64(
		int64(numMessageBits),
		progressbar.OptionSetDescription("decoding"),
		progressbar.OptionSetWriter(os.Stderr),
	)

	if *args.Strategy == "dct" {
		blockX := 0
		blockY := 1
		blocksW := width / 8

		for i := 0; i < numMessageBits; i++ {
			bar.Add(1)
			if blockX >= blocksW {
				blockX = 0
				blockY++
			}
			if blockY*8+8 > height {
				return errors.New("image too small for DCT message")
			}

			if decodeDCTBlock(img, blockX, blockY) != 0 {
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
			bar.Add(1)
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

	// Recover data using Reed-Solomon
	recoveredBytes, err := removeReedSolomon(messageBytes)
	if err != nil {
		return fmt.Errorf("Reed-Solomon reconstruction failed: %v", err)
	}

	var message string

	if *args.Passphrase != "" {
		decrypted, err := decrypt(recoveredBytes, *args.Passphrase, salt)
		if err != nil {
			return fmt.Errorf("failed to decrypt message: %v", err)
		}
		message = string(decrypted)

	} else if *args.PrivateKeyPath != "" {
		decryptedBytes, err := decryptRSA(recoveredBytes, *args.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("RSA decryption failed: %v", err)
		}
		message = string(decryptedBytes)

	} else {
		message = string(recoveredBytes)
	}

	if args.Output != nil && *args.Output != "" {
		return os.WriteFile(*args.Output, []byte(message), 0644)
	} else {
		fmt.Println(message)
	}
	return nil
}

func embedDCTBlock(img *image.NRGBA, blockX, blockY int, bit int) {
	// Extract Blue channel 8x8 block
	var block [8][8]float64
	baseX, baseY := blockX*8, blockY*8
	for bx := 0; bx < 8; bx++ {
		for by := 0; by < 8; by++ {
			pix := getPixel(img, baseX+bx, baseY+by)
			block[bx][by] = float64(pix[2]) // Blue channel
		}
	}

	// DCT
	dctBlock := dct2d(block)

	// Embed bit in (4,4) coefficient
	// Use a scaling factor to make the embedding robust against float->uint8 conversion noise
	const dctScale = 10.0
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
			pix := getPixel(img, baseX+bx, baseY+by)
			pix[2] = uint8(math.Max(0, math.Min(255, idctBlock[bx][by])))
		}
	}
}

func decodeDCTBlock(img *image.NRGBA, blockX, blockY int) int {
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
		return 1
	}
	return 0
}

// Reed-Solomon Configuration
const (
	rsDataShards   = 4
	rsParityShards = 2
)

func addReedSolomon(data []byte) ([]byte, error) {
	enc, err := reedsolomon.New(rsDataShards, rsParityShards)
	if err != nil {
		return nil, err
	}

	// Prepend length (4 bytes) to handle padding later
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	payload := append(header, data...)

	// Split into shards
	shards, err := enc.Split(payload)
	if err != nil {
		return nil, err
	}

	// Encode parity
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}

	// Join all shards (data + parity)
	var output []byte
	for _, shard := range shards {
		output = append(output, shard...)
	}
	return output, nil
}

func removeReedSolomon(data []byte) ([]byte, error) {
	enc, err := reedsolomon.New(rsDataShards, rsParityShards)
	if err != nil {
		return nil, err
	}

	// Split into shards (data + parity)
	shards, err := enc.Split(data)
	if err != nil {
		return nil, err
	}

	// Verify and Reconstruct if necessary
	if ok, _ := enc.Verify(shards); !ok {
		if err := enc.Reconstruct(shards); err != nil {
			return nil, err
		}
	}

	// Join data shards only
	var joined []byte
	for i := 0; i < rsDataShards; i++ {
		joined = append(joined, shards[i]...)
	}

	// Read original length
	if len(joined) < 4 {
		return nil, errors.New("recovered data too short")
	}
	length := binary.BigEndian.Uint32(joined[:4])
	if uint32(len(joined)) < 4+length {
		return nil, errors.New("recovered data length mismatch")
	}

	return joined[4 : 4+length], nil
}
