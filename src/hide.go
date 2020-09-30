package main

import (
	"errors"
	"fmt"
	"github.com/akamensky/argparse"
	"image"
	"image/png"
	_ "image/png"
	"math"
	"os"
)

//TODO: Make png/Encode more dynamic to work with other encoding types
//TODO: Make encoding a thing

func main() {
	parser := argparse.NewParser("HIDE", "Hide messages in images")
	generateCommand, generateArgs := initGenerateCommand(parser)
	concealCommand, concealArgs := initConcealCommand(parser)
	revealCommand, revealArgs := initRevealCommand(parser)

	if err := parser.Parse(os.Args); err != nil {
		fmt.Println(parser.Usage(err))

	} else if (*concealArgs.passphrase != "" && *concealArgs.publicKeyPath != "") ||
		(*revealArgs.passphrase != "" && *revealArgs.privateKeyPath != "") {
		fmt.Println(parser.Usage("passphrase and key-path cannot both be provided"))

	} else if generateCommand.Happened() {
		fmt.Println(generateArgs)

	} else if concealCommand.Happened() {

		if *concealArgs.output == "" {
			*concealArgs.output = fmt.Sprintf("%s.out", *concealArgs.imagePath)
		}

		if err := conceal(concealArgs); err != nil {
			fmt.Println(parser.Usage(err))
		}

	} else if revealCommand.Happened() && reveal(revealArgs) != nil {
		fmt.Println(parser.Usage(err))

	}
}

func conceal(args *ConcealArgs) error {
	img, err := loadImage(*args.imagePath)

	if err != nil {
		return err
	}

	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	messageBytes := []byte(*args.message)

	if *args.passphrase != "" {
		messageBytes = encrypt(messageBytes, *args.passphrase)
	}

	if *args.publicKeyPath != "" {
		return errors.New("PGP encryption not yet implemented")
	}

	totalBitsToBeWritten := len(messageBytes) * 8
	stepper := makeImageStepper(*args.numBitsPerChannel, width, height, *args.numChannels, totalBitsToBeWritten)
	outputImage := copyImage(img)
	totalBitsInImage := numBitsAvailable(width, height, 4, 8)
	pixels := outputImage.Pix

	// numBitsToEncodeNumMessageBits tells us how many bits to read from the image so we can decode the bits required
	// for the hidden message. We let numBitsToEncodeNumMessageBits be equal to the number of bits required to encode
	// the total number of bits in the image since the number of bits to encode a message cannot exceed the number
	// of bits to encode the number of bits in the entire image. This provides a fixed number of bits for each image
	// that can be calculated when concealing and revealing a message from an image.
	numBitsToEncodeNumMessageBits := int(math.Floor(math.Log2(float64(totalBitsInImage))))
	totalBitsAvailable := numBitsAvailable(width, height, *args.numChannels, *args.numBitsPerChannel)

	if *args.verbose {
		fmt.Println("Width:", width, "Height:", height)
		fmt.Println("Total bits in image:", totalBitsInImage)
		fmt.Println("Total bits available for use:", totalBitsAvailable)
		fmt.Println("Total bits to be written:", totalBitsToBeWritten)
	}

	if width+height < 2 {
		return errors.New("image must have at least 2 pixels")
	}

	if totalBitsAvailable < totalBitsToBeWritten+numBitsToEncodeNumMessageBits {
		return errors.New("image is not large enough to hide a message")
	}

	// Encode how many bits are used per channel
	// Since we only need to encode the numbers 1 to 8, we can use take least significant bit
	// from each of the first pixel's RGBA channels and use them to represent 1 to 8 since
	// 2^4 can represent numbers from 0 to 15

	for i := 0; i < 4; i++ {
		if getBit(*args.numBitsPerChannel, i) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.verbose {
		fmt.Println("Encoded number of bits per channel into the first pixel")
	}

	stepper.skipPixel()

	// Encode how many channels the encoding will use in the second pixel. Since we can only
	// have 1 to 4 channels as options, we can use the same technique as encoding the number
	// of bits used per channel (The block of code above)

	for i := 4; i < 8; i++ {
		if getBit(*args.numChannels, i-4) == 0 {
			pixels[i] = clearBitUint8(pixels[i], 0)
		} else {
			pixels[i] = setBitUint8(pixels[i], 0)
		}
	}

	if *args.verbose {
		fmt.Println("Encoded number of channels into the second pixel")
	}

	stepper.skipPixel()

	// Encode number of bits that will be written to the image
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

	if *args.verbose {
		fmt.Println("Encoded the number of bits that will be written")
	}

	// Write encrypted message to the image
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

	file, err := os.Create(*args.output)
	if err != nil {
		return err
	}

	err = png.Encode(file, outputImage)
	if err != nil {
		return err
	}

	if *args.verbose {
		fmt.Println("Encoded message into the image")
	}

	return nil
}

func reveal(args *RevealArgs) error {
	img, err := loadImage(*args.imagePath)

	if err != nil {
		return err
	}

	var channels []uint8
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y
	numBitsToUsePerChannel := 0
	numChannels := 0
	numMessageBits := 0

	// Extract numBitsToUsePerChannel from the least significant bits of the 4 channels in the first pixel
	channels = colorToChannels(img.At(0, 0))

	for i := 0; i < 4; i++ {
		channelValue := channels[i]

		if getBitUint8(channelValue, 0) == 0 {
			numBitsToUsePerChannel = clearBit(numBitsToUsePerChannel, i)
		} else {
			numBitsToUsePerChannel = setBit(numBitsToUsePerChannel, i)
		}
	}

	if *args.verbose {
		fmt.Println("Width:", width, "Height:", height)
		fmt.Println("Decoded number of bits to use per channel from first pixel:", numBitsToUsePerChannel)
	}

	// Extract numChannels from the least significant bits of the 4 channels in the second pixel
	// Since we're guaranteed to have at least two pixels (Because conceal() requires and exports
	// an image with at least 2 pixels, we need to make sure two grab the correct second pixel at
	// point (0, 1) or (1, 0)

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

	if *args.verbose {
		fmt.Println("Decoded number of channels from second pixel:", numChannels)
	}

	stepper := makeImageStepper(numBitsToUsePerChannel, width, height, numChannels, 0)
	stepper.skipPixel()
	stepper.skipPixel()

	// See func conceal for a description of numBitsToEncodeNumMessageBits
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

	if *args.verbose {
		fmt.Println("Decoded number of bits used to encode the message:", numMessageBits)
	}

	// Read encoded and possibly encrypted message from the image and write it to messageBytes
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

	if *args.verbose && (*args.passphrase != "" || *args.privateKeyPath != "") {
		fmt.Println("Decrypting message")
	}

	var message string

	if *args.passphrase != "" {
		message = string(decrypt(messageBytes, *args.passphrase))

	} else if *args.privateKeyPath != "" {
		return errors.New("PGP encryption not yet implemented")

	} else {
		message = string(messageBytes)
	}

	fmt.Println("Message:", message)
	return nil
}
