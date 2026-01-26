package stego

import (
	"bufio"
	"bytes"
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

const ChunkSize = 1 * 1024 * 1024    // 1MB chunks
const MaxChunkSize = 5 * 1024 * 1024 // 5MB limit for decoding safety

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
	Writer         io.Writer
}

func Conceal(args *ConcealArgs) error {
	img, err := loadImage(*args.ImagePath)

	if err != nil {
		return err
	}

	output := *args.Output
	if output == "" {
		output = fmt.Sprintf("%s.out", *args.ImagePath)
	}

	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	var reader io.Reader
	if args.File != nil && *args.File != "" {
		f, err := os.Open(*args.File)
		if err != nil {
			return fmt.Errorf("failed to open input file: %v", err)
		}
		defer f.Close()
		reader = f
	} else {
		reader = bytes.NewReader([]byte(*args.Message))
	}

	var seed int64
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	if *args.Passphrase != "" {
		seed = getSeed(*args.Passphrase)
	}

	// DCT Strategy requires a Linear header to avoid collision with blocks.
	// We force the stepper to be linear (seed 0) for the header writing phase.
	stepperSeed := seed
	numChannels := *args.NumChannels
	numBitsPerChannel := *args.NumBitsPerChannel

	if *args.Strategy == "dct" {
		stepperSeed = 0
		// Force header values to be consistent with DCT strategy
		// DCT effectively uses 1 channel (Blue) and custom encoding.
		numChannels = 1
		numBitsPerChannel = 1
	}

	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	numBitsToEncodeNumMessageBits := int(math.Ceil(math.Log2(float64(totalBitsInImage))))
	stepper, err := makeImageStepper(numBitsPerChannel, width, height, numChannels, stepperSeed, "lsb")
	if err != nil {
		return err
	}
	outputImage := copyImage(img)
	pixels := outputImage.Pix

	totalBitsAvailable := numBitsAvailable(width, height, numChannels, numBitsPerChannel)

	if *args.Verbose {
		log.Debug().Int("width", width).Int("height", height).Msg("Image dimensions")
		log.Debug().Int("bits", totalBitsInImage).Msg("Total bits in image")
		log.Debug().Int("available", totalBitsAvailable).Msg("Total bits available for use")
	}

	if width*height < 35 {
		return errors.New("image must have at least 35 pixels (header+salt)")
	}

	if *args.Strategy == "dct" && width < 8 {
		return errors.New("image width must be at least 8 pixels for DCT strategy")
	}

	if *args.Strategy == "dct" {
		headerPixels := 35 + numBitsToEncodeNumMessageBits
		safeZonePixels := width * 8
		if headerPixels > safeZonePixels {
			return fmt.Errorf("image too narrow for DCT header: header needs %d pixels, but only %d available in safe zone", headerPixels, safeZonePixels)
		}
	}

	// Streaming strategy:
	// Since the total size is unknown, write the body first to count the bits,
	// then rewind to write the header with the correct length.

	// Advance stepper past Header, Salt, and Length field
	// Header (3 pixels) + Salt (32 pixels) = 35 pixels.
	// Length field = numBitsToEncodeNumMessageBits.

	for i := 0; i < 35; i++ {
		if err := stepper.skipPixel(); err != nil {
			return fmt.Errorf("failed to skip header pixels: %v", err)
		}
	}

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		if err := stepper.step(); err != nil {
			return fmt.Errorf("image too small to hold header: %v", err)
		}
	}

	bodyStepper := stepper
	if *args.Strategy == "dct" {
		bodyStepper, err = makeImageStepper(1, width, height, 1, 0, "dct")
		if err != nil {
			return err
		}
	}

	totalBitsWritten := 0
	buffer := make([]byte, ChunkSize)
	bar := progressbar.Default(-1, "encoding")

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			bar.Add(n)

			if *args.Passphrase != "" {
				chunk, err = encrypt(chunk, *args.Passphrase, salt)
				if err != nil {
					return err
				}
			} else if *args.PublicKeyPath != "" {
				chunk, err = encryptRSA(chunk, *args.PublicKeyPath)
				if err != nil {
					return fmt.Errorf("RSA encryption failed: %v", err)
				}
			}

			chunk, err = addReedSolomon(chunk)
			if err != nil {
				return fmt.Errorf("RS encoding failed: %v", err)
			}

			chunkLen := uint32(len(chunk))
			chunkLenBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkLenBytes, chunkLen)

			if err := writeBytesToImage(outputImage, bodyStepper, chunkLenBytes, *args.Strategy, width, height); err != nil {
				return err
			}
			totalBitsWritten += 32

			if err := writeBytesToImage(outputImage, bodyStepper, chunk, *args.Strategy, width, height); err != nil {
				return err
			}
			totalBitsWritten += len(chunk) * 8
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if *args.Verbose {
		log.Debug().Int("totalBitsWritten", totalBitsWritten).Msg("Finished writing body")
	}

	stepper, err = makeImageStepper(numBitsPerChannel, width, height, numChannels, stepperSeed, "lsb")
	if err != nil {
		return err
	}

	// Write Header Info (Channels, Bits, Strategy)
	// Pixel 0: Bits Per Channel
	// Pixel 1: Num Channels
	// Pixel 2: Strategy
	// Pixel 3..34: Salt

	// Manually manipulate the first few pixels for the header to ensure exact placement.
	// This matches the Reveal expectation where the header is read linearly before the stepper takes over.

	for i := 0; i < 4; i++ {
		if getBit(numBitsPerChannel, i) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.Verbose {
		log.Debug().Msg("Encoded number of bits per channel into the first pixel")
	}

	if err := stepper.skipPixel(); err != nil {
		return err
	}

	for i := 4; i < 8; i++ {
		if getBit(numChannels, i-4) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.Verbose {
		log.Debug().Msg("Encoded number of channels into the second pixel")
	}

	if err := stepper.skipPixel(); err != nil {
		return err
	}

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
	if err := stepper.skipPixel(); err != nil {
		return err
	}

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
			if err := stepper.skipPixel(); err != nil {
				return err
			}
		} // Advance stepper every 4 channels (1 pixel)
	}

	// Write Total Length (bits)
	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		pixel := getPixel(outputImage, stepper.x, stepper.y)
		channelValue := pixel[stepper.channel]

		if getBit(totalBitsWritten, i) == 0 {
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

	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := png.Encode(file, outputImage); err != nil {
		return err
	}

	if *args.Verbose {
		log.Info().Str("output", output).Msg("Encoded message into the image")
	}

	return file.Close()
}

// writeBytesToImage writes a byte slice to the image using the stepper and strategy.
func writeBytesToImage(img *image.NRGBA, stepper *ImageStepper, data []byte, strategy string, width, height int) error {
	if strategy == "dct" {
		for _, b := range data {
			for i := 0; i < 8; i++ {
				// Use stepper coordinates as block coordinates
				blockX, blockY := stepper.x, stepper.y

				bit := getBitUint8(b, i)
				embedDCTBlock(img, blockX, blockY, bit)

				if err := stepper.step(); err != nil {
					return err
				}
			}
		}
		return nil
	}

	matching := strategy == "lsb-matching"
	var rng *bufio.Reader
	if matching {
		rng = bufio.NewReader(rand.Reader)
	}

	for _, b := range data {
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

func Reveal(args *RevealArgs) ([]byte, error) {
	imgRaw, err := loadImage(*args.ImagePath)
	if err != nil {
		return nil, err
	}
	// Convert to NRGBA to ensure consistent pixel access and avoid type assertion panics
	img := copyImage(imgRaw)
	pixels := img.Pix

	var channels []uint8
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y
	numBitsToUsePerChannel := 0

	if width*height < 35 {
		return nil, errors.New("image must have at least 35 pixels (header+salt)")
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
		return nil, fmt.Errorf("invalid header: detected %d channels (must be 1-4)", numChannels)
	}
	if numBitsToUsePerChannel < 1 || numBitsToUsePerChannel > 8 {
		return nil, fmt.Errorf("invalid header: detected %d bits per channel (must be 1-8)", numBitsToUsePerChannel)
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
	stepper, err := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, stepperSeed, "lsb")
	if err != nil {
		return nil, err
	}
	if err := stepper.skipPixel(); err != nil {
		return nil, err
	}
	if err := stepper.skipPixel(); err != nil {
		return nil, err
	}
	if err := stepper.skipPixel(); err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		if err := stepper.skipPixel(); err != nil {
			return nil, err
		}
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
			return nil, err
		}
	}

	// Validate message length against capacity
	var capacity int
	if *args.Strategy == "dct" {
		if width < 8 {
			return nil, errors.New("image width must be at least 8 pixels for DCT strategy to fit header")
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
		return nil, fmt.Errorf("invalid header: message length %d exceeds capacity %d", numMessageBits, capacity)
	}
	if numMessageBits%8 != 0 {
		return nil, fmt.Errorf("invalid header: message length %d is not a multiple of 8", numMessageBits)
	}

	if *args.Verbose {
		log.Debug().Int("messageBits", numMessageBits).Msg("Decoded number of bits used to encode the message")
	}

	bar := progressbar.NewOptions64(
		int64(numMessageBits),
		progressbar.OptionSetDescription("decoding"),
		progressbar.OptionSetWriter(os.Stderr),
	)

	bitsReadTotal := 0

	// If no writer provided, buffer it (backward compatibility for tests)
	var outWriter io.Writer
	var outBuf bytes.Buffer
	if args.Writer != nil {
		outWriter = args.Writer
	} else {
		outWriter = &outBuf
	}

	// Switch to Body Stepper
	bodyStepper := stepper
	if *args.Strategy == "dct" {
		bodyStepper, err = makeImageStepper(1, width, height, 1, 0, "dct")
		if err != nil {
			return nil, err
		}
	}

	for bitsReadTotal < numMessageBits {
		chunkLenBytes, err := readBytesFromImage(img, bodyStepper, 4, *args.Strategy, width, height)
		if err != nil {
			return nil, err
		}
		bitsReadTotal += 32
		bar.Add(32)

		chunkLen := binary.BigEndian.Uint32(chunkLenBytes)
		if chunkLen > MaxChunkSize {
			return nil, fmt.Errorf("chunk length %d exceeds maximum allowed size", chunkLen)
		}

		chunkData, err := readBytesFromImage(img, bodyStepper, int(chunkLen), *args.Strategy, width, height)
		if err != nil {
			return nil, err
		}
		bitsReadTotal += int(chunkLen) * 8
		bar.Add(int(chunkLen) * 8)

		recovered, err := removeReedSolomon(chunkData)
		if err != nil {
			return nil, fmt.Errorf("RS decode failed: %v", err)
		}

		var decrypted []byte
		if *args.Passphrase != "" {
			decrypted, err = decrypt(recovered, *args.Passphrase, salt)
			if err != nil {
				return nil, fmt.Errorf("decrypt failed: %v", err)
			}
		} else if *args.PrivateKeyPath != "" {
			decrypted, err = decryptRSA(recovered, *args.PrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("RSA decrypt failed: %v", err)
			}
		} else {
			decrypted = recovered
		}

		if _, err := outWriter.Write(decrypted); err != nil {
			return nil, err
		}
	}

	if args.Writer == nil {
		return outBuf.Bytes(), nil
	}
	return nil, nil
}

func readBytesFromImage(img *image.NRGBA, stepper *ImageStepper, numBytes int, strategy string, width, height int) ([]byte, error) {
	out := make([]byte, numBytes)

	if strategy == "dct" {
		for i := 0; i < numBytes; i++ {
			for bitIdx := 0; bitIdx < 8; bitIdx++ {
				blockX, blockY := stepper.x, stepper.y

				if decodeDCTBlock(img, blockX, blockY) != 0 {
					out[i] = setBitUint8(out[i], bitIdx)
				} else {
					out[i] = clearBitUint8(out[i], bitIdx)
				}
				if err := stepper.step(); err != nil {
					return nil, err
				}
			}
		}
		return out, nil
	}

	numBitsRead := 0
	byteIndex := 0
	totalBits := numBytes * 8

	for j := 0; j < totalBits; j++ {
		channels := colorToChannels(img.At(stepper.x, stepper.y))
		channelValue := channels[stepper.channel]

		if getBitUint8(channelValue, stepper.bitIndexOffset) == 0 {
			out[byteIndex] = clearBitUint8(out[byteIndex], numBitsRead)
		} else {
			out[byteIndex] = setBitUint8(out[byteIndex], numBitsRead)
		}

		if numBitsRead++; numBitsRead == 8 {
			numBitsRead = 0
			byteIndex++
		}

		if err := stepper.step(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func embedDCTBlock(img *image.NRGBA, blockX, blockY int, bit int) {
	// Extract Blue channel 8x8 block
	var block [8][8]float64
	baseX, baseY := blockX*8, blockY*8
	for bx := 0; bx < 8; bx++ {
		for by := 0; by < 8; by++ {
			pix := getPixel(img, baseX+bx, baseY+by)
			block[bx][by] = float64(pix[2]) // Blue channel
			block[bx][by] = float64(pix[2])
		}
	}

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

	idctBlock := idct2d(dctBlock)

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

	dctBlock := dct2d(block)
	const dctScale = 10.0
	q := int(math.Round(dctBlock[4][4] / dctScale))

	if (q%2+2)%2 != 0 {
		return 1
	}
	return 0
}

const (
	rsDataShards   = 4
	rsParityShards = 2
)

func addReedSolomon(data []byte) ([]byte, error) {
	enc, err := reedsolomon.New(rsDataShards, rsParityShards)
	if err != nil {
		return nil, err
	}

	// Prepend length (8 bytes) to handle padding later
	length := uint64(len(data))
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, length)
	payload := append(header, data...)

	shards, err := enc.Split(payload)
	if err != nil {
		return nil, err
	}

	if err := enc.Encode(shards); err != nil {
		return nil, err
	}

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

	var joined []byte
	for i := 0; i < rsDataShards; i++ {
		joined = append(joined, shards[i]...)
	}

	// Read original length
	if len(joined) < 8 {
		return nil, errors.New("recovered data too short")
	}
	length := binary.BigEndian.Uint64(joined[:8])
	if length > uint64(len(joined))-8 {
		return nil, errors.New("recovered data length mismatch")
	}

	return joined[8 : 8+length], nil
}
