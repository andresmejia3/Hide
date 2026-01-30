package stego

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

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
	NumWorkers        *int
	DryRun            *bool
	Compress          *bool
}

type RevealArgs struct {
	ImagePath      *string
	Passphrase     *string
	PrivateKeyPath *string
	Encoding       *string
	Verbose        *bool
	Strategy       *string
	Writer         io.Writer
	NumWorkers     *int
}

type VerifyArgs struct {
	ImagePath  *string
	Passphrase *string
	Verbose    *bool
	NumWorkers *int
}

type VerifyResult struct {
	Strategy       string
	MessageBits    int
	NumChannels    int
	BitsPerChannel int
}

type AnalyzeArgs struct {
	OriginalPath *string
	StegoPath    *string
	HeatmapPath  *string
}

func Conceal(args *ConcealArgs) error {
	log.Info().Msg("📂 Loading image...")
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
	var inputSize int64 = -1

	if args.File != nil && *args.File != "" {
		if *args.File == "-" {
			reader = os.Stdin
			log.Info().Msg("📖 Reading message from Stdin...")
		} else {
			f, err := os.Open(*args.File)
			if err != nil {
				return fmt.Errorf("failed to open input file: %v", err)
			}
			defer f.Close()
			if info, err := f.Stat(); err == nil {
				inputSize = info.Size()
			}
			reader = f
		}
	} else {
		inputBytes := []byte(*args.Message)
		reader = bytes.NewReader(inputBytes)
		inputSize = int64(len(inputBytes))
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

	// Estimate required capacity
	// Header (35 pixels * channels * bits) is skipped by stepper logic, but let's approximate.
	// We need:
	// Header pixels (skipped)
	// Message Length (32 bits approx)
	// Message Body (inputSize * 8)
	// Reed-Solomon Overhead (approx 1.5x for 4 data / 2 parity)
	// Encryption overhead (IV/Salt/Key)

	if inputSize > 0 {
		estimatedBitsNeeded := int(inputSize * 8 * 3 / 2) // Rough 1.5x estimate for RS + overhead
		if estimatedBitsNeeded > totalBitsAvailable {
			log.Warn().Int("available", totalBitsAvailable).Int("needed_approx", estimatedBitsNeeded).Msg("Image might be too small for this message")
		}

		if args.DryRun != nil && *args.DryRun {
			log.Info().Int("available_bits", totalBitsAvailable).Int("estimated_needed_bits", estimatedBitsNeeded).Msg("Dry run capacity check")
			if estimatedBitsNeeded > totalBitsAvailable {
				return fmt.Errorf("image is too small: needed ~%d bits, available %d bits", estimatedBitsNeeded, totalBitsAvailable)
			}
			log.Info().Msg("✅ Image has sufficient capacity for this message")
			return nil
		}
	} else if args.DryRun != nil && *args.DryRun {
		log.Info().Int("available_bits", totalBitsAvailable).Msg("Dry run capacity check (input size unknown)")
		log.Info().Msg("✅ Image capacity calculated. Input size unknown (stream), skipping size check.")
		return nil
	}

	if *args.Verbose {
		log.Debug().Int("width", width).Int("height", height).Msg("Image dimensions")
		log.Debug().Int("bits", totalBitsInImage).Msg("Total bits in image")
		log.Debug().Int("available", totalBitsAvailable).Msg("Total bits available for use")
	}

	if width*height < HeaderPixels {
		return fmt.Errorf("image must have at least %d pixels (header+salt)", HeaderPixels)
	}

	if *args.Strategy == "dct" && width < 8 {
		return errors.New("image width must be at least 8 pixels for DCT strategy")
	}

	if *args.Strategy == "dct" {
		headerPixels := HeaderPixels + numBitsToEncodeNumMessageBits
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

	for i := 0; i < HeaderPixels; i++ {
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

	numWorkers := runtime.NumCPU()
	if args.NumWorkers != nil && *args.NumWorkers > 0 {
		numWorkers = *args.NumWorkers
	}

	totalBitsWritten := 0
	buffer := make([]byte, ChunkSize)
	bar := progressbar.NewOptions64(
		inputSize,
		progressbar.OptionSetDescription(" 🔒 Encoding"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]

			if args.Compress != nil && *args.Compress {
				chunk, err = compressData(chunk)
				if err != nil {
					return fmt.Errorf("compression failed: %v", err)
				}
			}

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

			if err := writeBytesToImage(outputImage, bodyStepper, chunkLenBytes, *args.Strategy, width, height, numWorkers); err != nil {
				if errors.Is(err, ErrIteratorExhausted) {
					return fmt.Errorf("image is too small to hold the data")
				}
				return err
			}
			totalBitsWritten += 32

			if err := writeBytesToImage(outputImage, bodyStepper, chunk, *args.Strategy, width, height, numWorkers); err != nil {
				if errors.Is(err, ErrIteratorExhausted) {
					return fmt.Errorf("image is too small to hold the data")
				}
				return err
			}
			totalBitsWritten += len(chunk) * 8
			bar.Add(n)
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
	// Use bit 2 (value 4) to indicate compression
	if args.Compress != nil && *args.Compress {
		strategyID = strategyID | 4
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

	log.Info().Msg("💾 Saving output image...")

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

	log.Info().Msg("✨ Done!")

	return file.Close()
}

// writeBytesToImage writes a byte slice to the image using the stepper and strategy.
func writeBytesToImage(img *image.NRGBA, stepper *ImageStepper, data []byte, strategy string, width, height int, numWorkers int) error {
	// DCT strategy is CPU intensive (floating point math per bit).
	// We use a worker pool to parallelize the embedding of blocks.
	if strategy == "dct" {
		type dctJob struct {
			x, y, bit int
		}

		// Use a context to signal cancellation to all workers and the producer.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel() // Ensure cancellation is called on function exit.

		jobs := make(chan dctJob, 1000) // Buffer to keep workers fed
		errChan := make(chan error, 1)  // Buffered channel to hold the first error.
		var wg sync.WaitGroup

		// Start workers
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					// Before starting work, check if cancellation has been requested.
					select {
					case <-ctx.Done():
						return
					default:
					}

					if err := embedDCTBlock(img, job.x, job.y, job.bit); err != nil {
						// On error, try to send it. If successful, we were the first.
						// Cancel all other goroutines.
						select {
						case errChan <- err:
							cancel()
						default:
						}
						return // Stop this worker.
					}
				}
			}()
		}

		// Feed jobs to workers, but exit early if context is cancelled.
	producerLoop:
		for _, b := range data {
			for i := 0; i < 8; i++ {
				// Calculate coordinates sequentially using the stepper
				blockX, blockY := stepper.x, stepper.y
				bit := getBitUint8(b, i)
				job := dctJob{blockX, blockY, bit}

				// Send to worker
				select {
				case jobs <- job:
				case <-ctx.Done():
					break producerLoop
				}

				if err := stepper.step(); err != nil {
					// Stepper failed (e.g., out of space). Report error and cancel.
					select {
					case errChan <- err:
					default:
					}
					cancel()
					break producerLoop
				}
			}
		}
		close(jobs) // Signal workers that no more jobs are coming.
		wg.Wait()   // Wait for all workers to finish.

		// Return the first error that occurred, if any.
		select {
		case err := <-errChan:
			return err
		default:
			return nil
		}
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
	log.Info().Msg("📂 Loading image...")
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

	if width*height < HeaderPixels {
		return nil, fmt.Errorf("image must have at least %d pixels (header+salt)", HeaderPixels)
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

	isCompressed := false

	// Decode Strategy ID from the third pixel
	channels = pixels[8:12]
	strategyID := 0
	for i := 0; i < 4; i++ {
		if getBitUint8(channels[i], 0) != 0 {
			strategyID = setBit(strategyID, i)
		}
	}

	// Check for compression bit (bit 2, value 4)
	if (strategyID & 4) != 0 {
		isCompressed = true
		strategyID = strategyID & 3 // Strip compression bit to get strategy
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
		capacity -= HeaderPixels * numChannels * numBitsToUsePerChannel
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
		progressbar.OptionSetDescription(" 🔓 Decoding"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
	bar.RenderBlank()

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

	numWorkers := runtime.NumCPU()
	if args.NumWorkers != nil && *args.NumWorkers > 0 {
		numWorkers = *args.NumWorkers
	}

	for bitsReadTotal < numMessageBits {
		chunkLenBytes, err := readBytesFromImage(img, bodyStepper, 4, *args.Strategy, width, height, numWorkers, func(n int) {
			bar.Add(n)
		})
		if err != nil {
			return nil, err
		}
		bitsReadTotal += 32

		chunkLen := binary.BigEndian.Uint32(chunkLenBytes)
		if chunkLen > MaxChunkSize {
			return nil, fmt.Errorf("chunk length %d exceeds maximum allowed size", chunkLen)
		}

		chunkData, err := readBytesFromImage(img, bodyStepper, int(chunkLen), *args.Strategy, width, height, numWorkers, func(n int) {
			bar.Add(n)
		})
		if err != nil {
			return nil, err
		}
		bitsReadTotal += int(chunkLen) * 8

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

		if isCompressed {
			decrypted, err = decompressData(decrypted)
			if err != nil {
				return nil, fmt.Errorf("decompression failed: %v", err)
			}
		}

		if _, err := outWriter.Write(decrypted); err != nil {
			return nil, err
		}
	}

	if args.Writer == nil {
		return outBuf.Bytes(), nil
	}
	log.Info().Msg("✨ Done!")
	return nil, nil
}

func Verify(args *VerifyArgs) (*VerifyResult, error) {
	log.Info().Msg("📂 Loading image...")
	imgRaw, err := loadImage(*args.ImagePath)
	if err != nil {
		return nil, err
	}
	img := copyImage(imgRaw)
	pixels := img.Pix

	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	if width*height < HeaderPixels {
		return nil, fmt.Errorf("image must have at least %d pixels (header+salt)", HeaderPixels)
	}

	// Parse Header
	var channels []uint8
	numBitsToUsePerChannel := 0
	channels = pixels[0:4]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels[i], 0) != 0 {
			numBitsToUsePerChannel = setBit(numBitsToUsePerChannel, i)
		}
	}

	numChannels := 0
	channels = pixels[4:8]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels[i], 0) != 0 {
			numChannels = setBit(numChannels, i)
		}
	}

	strategyID := 0
	channels = pixels[8:12]
	for i := 0; i < 4; i++ {
		if getBitUint8(channels[i], 0) != 0 {
			strategyID = setBit(strategyID, i)
		}
	}

	strategy := "lsb"
	switch strategyID {
	case 1:
		strategy = "lsb-matching"
	case 2:
		strategy = "dct"
	}

	if numChannels < 1 || numChannels > 4 {
		return nil, fmt.Errorf("invalid header: detected %d channels (must be 1-4)", numChannels)
	}
	if numBitsToUsePerChannel < 1 || numBitsToUsePerChannel > 8 {
		return nil, fmt.Errorf("invalid header: detected %d bits per channel (must be 1-8)", numBitsToUsePerChannel)
	}

	if *args.Verbose {
		log.Debug().Str("strategy", strategy).Int("channels", numChannels).Int("bits", numBitsToUsePerChannel).Msg("Header parsed")
	}

	var seed int64
	if *args.Passphrase != "" {
		seed = getSeed(*args.Passphrase)
	}

	stepperSeed := seed
	if strategy == "dct" {
		stepperSeed = 0
	}

	stepper, err := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, stepperSeed, "lsb")
	if err != nil {
		return nil, err
	}

	// Skip header (HeaderPixels)
	for i := 0; i < HeaderPixels; i++ {
		if err := stepper.skipPixel(); err != nil {
			return nil, err
		}
	}

	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	numBitsToEncodeNumMessageBits := int(math.Ceil(math.Log2(float64(totalBitsInImage))))
	numMessageBits := 0

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		chans := colorToChannels(img.At(stepper.x, stepper.y))
		val := chans[stepper.channel]
		if getBitUint8(val, stepper.bitIndexOffset) != 0 {
			numMessageBits = setBit(numMessageBits, i)
		}
		if err := stepper.step(); err != nil {
			return nil, err
		}
	}

	if numMessageBits < 0 || numMessageBits%8 != 0 {
		return nil, fmt.Errorf("invalid header: message length %d is invalid", numMessageBits)
	}

	bar := progressbar.NewOptions64(
		int64(numMessageBits),
		progressbar.OptionSetDescription(" 🔍 Verifying"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
	bar.RenderBlank()

	bodyStepper := stepper
	if strategy == "dct" {
		bodyStepper, err = makeImageStepper(1, width, height, 1, 0, "dct")
		if err != nil {
			return nil, err
		}
	}

	numWorkers := runtime.NumCPU()
	if args.NumWorkers != nil && *args.NumWorkers > 0 {
		numWorkers = *args.NumWorkers
	}

	bitsReadTotal := 0
	for bitsReadTotal < numMessageBits {
		chunkLenBytes, err := readBytesFromImage(img, bodyStepper, 4, strategy, width, height, numWorkers, func(n int) {
			bar.Add(n)
		})
		if err != nil {
			return nil, err
		}
		bitsReadTotal += 32

		chunkLen := binary.BigEndian.Uint32(chunkLenBytes)
		if chunkLen > MaxChunkSize {
			return nil, fmt.Errorf("chunk length %d exceeds maximum allowed size", chunkLen)
		}

		chunkData, err := readBytesFromImage(img, bodyStepper, int(chunkLen), strategy, width, height, numWorkers, func(n int) {
			bar.Add(n)
		})
		if err != nil {
			return nil, err
		}
		bitsReadTotal += int(chunkLen) * 8

		// Verify integrity using Reed-Solomon
		if _, err := removeReedSolomon(chunkData); err != nil {
			return nil, fmt.Errorf("integrity check failed: %v", err)
		}
	}

	log.Info().Msg("✨ Done!")
	return &VerifyResult{
		Strategy:       strategy,
		MessageBits:    numMessageBits,
		NumChannels:    numChannels,
		BitsPerChannel: numBitsToUsePerChannel,
	}, nil
}

func readBytesFromImage(img *image.NRGBA, stepper *ImageStepper, numBytes int, strategy string, width, height int, numWorkers int, onProgress func(int)) ([]byte, error) {
	out := make([]byte, numBytes)

	if strategy == "dct" {
		type readJob struct {
			byteIdx int
			bitIdx  int
			x, y    int
		}
		type readResult struct {
			byteIdx int
			bitIdx  int
			bit     int
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		jobs := make(chan readJob, 1000)
		results := make(chan readResult, 1000)
		errChan := make(chan error, 1)
		var wg sync.WaitGroup

		// Start workers
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}

					bit := decodeDCTBlock(img, job.x, job.y)

					select {
					case results <- readResult{job.byteIdx, job.bitIdx, bit}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// Start collector to aggregate results into the output slice
		collectorDone := make(chan struct{})
		go func() {
			defer close(collectorDone)
			pendingProgress := 0
			for res := range results {
				if res.bit != 0 {
					out[res.byteIdx] = setBitUint8(out[res.byteIdx], res.bitIdx)
				}
				// No need to clear bit since out is initialized to 0s
				pendingProgress++
				if pendingProgress >= 1000 {
					if onProgress != nil {
						onProgress(pendingProgress)
					}
					pendingProgress = 0
				}
			}
			if pendingProgress > 0 && onProgress != nil {
				onProgress(pendingProgress)
			}
		}()

		// Producer loop
	producerLoop:
		for i := 0; i < numBytes; i++ {
			for bitIdx := 0; bitIdx < 8; bitIdx++ {
				blockX, blockY := stepper.x, stepper.y

				select {
				case jobs <- readJob{i, bitIdx, blockX, blockY}:
				case <-ctx.Done():
					break producerLoop
				}

				if err := stepper.step(); err != nil {
					select {
					case errChan <- err:
					default:
					}
					cancel()
					break producerLoop
				}
			}
		}
		close(jobs)
		wg.Wait()      // Wait for workers
		close(results) // Signal collector to finish
		<-collectorDone

		select {
		case err := <-errChan:
			return nil, err
		default:
			return out, nil
		}
	}

	numBitsRead := 0
	byteIndex := 0
	totalBits := numBytes * 8
	pendingProgress := 0

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
		pendingProgress++
		if pendingProgress >= 1000 {
			if onProgress != nil {
				onProgress(pendingProgress)
			}
			pendingProgress = 0
		}
	}
	if pendingProgress > 0 && onProgress != nil {
		onProgress(pendingProgress)
	}
	return out, nil
}

func calculateBlockVariance(block [8][8]float64) float64 {
	var sum float64
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			sum += block[i][j]
		}
	}
	mean := sum / 64.0

	var variance float64
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			variance += (block[i][j] - mean) * (block[i][j] - mean)
		}
	}
	return variance / 64.0
}

func getAdaptiveScale(variance float64) float64 {
	const minScale = 20.0
	const maxScale = 80.0
	const minVariance = 5.0
	const maxVariance = 250.0

	if variance < minVariance {
		return minScale
	}
	if variance > maxVariance {
		return maxScale
	}

	// Linear interpolation
	scale := minScale + (variance-minVariance)*(maxScale-minScale)/(maxVariance-minVariance)
	return scale
}

func embedDCTBlock(img *image.NRGBA, blockX, blockY int, bit int) error {
	// Extract Blue channel 8x8 block
	originalPixels := make([]uint8, 64)
	var block [8][8]float64
	baseX, baseY := blockX*8, blockY*8
	for bx := 0; bx < 8; bx++ {
		for by := 0; by < 8; by++ {
			pix := getPixel(img, baseX+bx, baseY+by)
			val := pix[2]
			block[bx][by] = float64(val) // Blue channel
			originalPixels[by*8+bx] = val
		}
	}

	variance := calculateBlockVariance(block)
	var dctBlock [8][8]float64
	dct2d(&block, &dctBlock)

	// Use an adaptive scale and a lower frequency coefficient for better robustness/imperceptibility
	dctScale := getAdaptiveScale(variance)
	val := dctBlock[1][2]
	q := int(math.Round(val / dctScale))

	// Ensure q % 2 matches the bit
	if (q%2+2)%2 != bit {
		if val < float64(q)*dctScale {
			q--
		} else {
			q++
		}
	}

	// Iteratively attempt to embed the bit, adjusting q if quantization noise flips it back
	originalQ := q
	var idctBlock [8][8]float64
	// Try progressively larger shifts to force the bit to stick
	// We iterate dynamically to cover a wider range if necessary (up to +/- 50)
	for i := 0; i <= 25; i++ {
		candidates := []int{originalQ + (i * 2)}
		if i > 0 {
			candidates = append(candidates, originalQ-(i*2))
		}

		for _, tryQ := range candidates {
			q = tryQ
			dctBlock[1][2] = float64(q) * dctScale
			idct2d(&dctBlock, &idctBlock)

			for bx := 0; bx < 8; bx++ {
				for by := 0; by < 8; by++ {
					pix := getPixel(img, baseX+bx, baseY+by)
					pix[2] = uint8(math.Max(0, math.Min(255, idctBlock[bx][by])))
				}
			}

			// Verify if the bit persists after round-trip
			if decodeDCTBlock(img, blockX, blockY) == bit {
				return nil
			}
			// If verification failed, restore original pixels for the next attempt.
			for bx := 0; bx < 8; bx++ {
				for by := 0; by < 8; by++ {
					pix := getPixel(img, baseX+bx, baseY+by)
					pix[2] = originalPixels[by*8+bx]
				}
			}
		}
	}
	return fmt.Errorf("failed to embed bit in DCT block at %d,%d after multiple attempts", blockX, blockY)
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

	variance := calculateBlockVariance(block)
	var dctBlock [8][8]float64
	dct2d(&block, &dctBlock)
	dctScale := getAdaptiveScale(variance)
	q := int(math.Round(dctBlock[1][2] / dctScale))

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

func compressData(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decompressData(data []byte) ([]byte, error) {
	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	res, err := io.ReadAll(r)
	r.Close()
	return res, err
}

// GetCapacity calculates the maximum number of bits that can be hidden in an image
// with the given dimensions and settings.
func GetCapacity(width, height, channels, bits int, strategy string) int {
	if strategy == "dct" {
		// DCT implementation uses 8x8 blocks.
		// It skips the first row of blocks (y=0) for the header.
		blocksW := width / 8
		blocksH := height / 8
		if blocksH <= 1 {
			return 0
		}
		return blocksW * (blocksH - 1)
	}
	return numBitsAvailable(width, height, channels, bits)
}
