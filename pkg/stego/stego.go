package stego

import (
	"errors"
	"fmt"
	"image"
	"image/png"
	_ "image/png"
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
}

type RevealArgs struct {
	ImagePath      *string
	Passphrase     *string
	PrivateKeyPath *string
	Encoding       *string
	Verbose        *bool
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

	if *args.Passphrase != "" {
		messageBytes = encrypt(messageBytes, *args.Passphrase)
	}

	if *args.PublicKeyPath != "" {
		messageBytes, err = encryptRSA(messageBytes, *args.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("RSA encryption failed: %v", err)
		}
	}

	totalBitsToBeWritten := len(messageBytes) * 8
	stepper := makeImageStepper(*args.NumBitsPerChannel, width, height, *args.NumChannels, totalBitsToBeWritten)
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

	if width+height < 2 {
		return errors.New("image must have at least 2 pixels")
	}

	if totalBitsAvailable < totalBitsToBeWritten+numBitsToEncodeNumMessageBits {
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

	for i := 0; i < numBitsToEncodeNumMessageBits; i++ {
		pixel := getPixel(outputImage, stepper.x, stepper.y)
		channels := colorToChannels(img.At(stepper.x, stepper.y))
		channelValue := channels[stepper.channel]

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

	for _, encryptedByte := range messageBytes {
		for i := 0; i < 8; i++ {
			channels := colorToChannels(img.At(stepper.x, stepper.y))
			channelValue := channels[stepper.channel]
			pixel := getPixel(outputImage, stepper.x, stepper.y)

			if bit := getBitUint8(encryptedByte, i); bit == 0 {
				pixel[stepper.channel] = clearBitUint8(channelValue, stepper.bitIndexOffset)
			} else {
				pixel[stepper.channel] = setBitUint8(channelValue, stepper.bitIndexOffset)
			}

			if err := stepper.step(); err != nil {
				return err
			}

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

func Reveal(args *RevealArgs) error {
	img, err := loadImage(*args.ImagePath)

	if err != nil {
		return err
	}

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

	if *args.Verbose {
		log.Debug().Int("channels", numChannels).Msg("Decoded number of channels")
	}

	stepper := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, 0)
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

	if *args.Verbose {
		log.Debug().Int("messageBits", numMessageBits).Msg("Decoded number of bits used to encode the message")
	}

	messageBytes := make([]byte, numMessageBits/8)
	numBitsRead := 0
	byteIndex := 0

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

	if *args.Verbose && (*args.Passphrase != "" || *args.PrivateKeyPath != "") {
		log.Debug().Msg("Decrypting message")
	}

	var message string

	if *args.Passphrase != "" {
		message = string(decrypt(messageBytes, *args.Passphrase))

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
