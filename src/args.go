package main

import (
	"errors"
	"github.com/akamensky/argparse"
	"strconv"
)

type ConcealArgs struct {
	imagePath         *string
	passphrase        *string
	publicKeyPath     *string
	message           *string
	output            *string
	numBitsPerChannel *int
	encoding          *string
	numChannels       *int
	verbose           *bool
}

type RevealArgs struct {
	imagePath      *string
	passphrase     *string
	privateKeyPath *string
	encoding       *string
	verbose        *bool
}

type GenerateArgs struct {
	numBytes   *int
	outputPath *string
}

func nonEmptyStringValidator(args []string) error {
	if args[0] == "" {
		return errors.New("arguments cannot be an empty strings")
	}
	return nil
}

func byteIndexValidator(args []string) error {
	num, err := strconv.Atoi(args[0])

	if err != nil {
		return err
	}

	if num < 0 || num > 8 {
		return errors.New("maximum number of bits to use per channel is 8")
	}

	return nil
}

func numChannelsValidator(args []string) error {
	num, err := strconv.Atoi(args[0])

	if err != nil {
		return err
	}

	if num < 0 || num > 4 {
		return errors.New("channels argument can only be 1, 2, 3, or 4")
	}

	return nil
}

func initGenerateCommand(parser *argparse.Parser) (*argparse.Command, *GenerateArgs) {
	generateCommand := parser.NewCommand("generate", "Generate a pair of public and private key")
	generateArgs := &GenerateArgs{}

	generateArgs.numBytes = generateCommand.Int("n", "num-bytes", &argparse.Options{
		Required: false,
		Default:  2048,
		Help:     "Number of bytes to use for public and private key lengths",
	})

	generateArgs.outputPath = generateCommand.String("o", "output", &argparse.Options{
		Required: true,
		Help:     "Path to directory where the generated public and private keys should be saved to",
		Validate: nonEmptyStringValidator,
	})

	return generateCommand, generateArgs
}

func initConcealCommand(parser *argparse.Parser) (*argparse.Command, *ConcealArgs) {
	concealArgs := &ConcealArgs{}

	concealCommand := parser.NewCommand("conceal", "Conceal a message in an image")

	concealArgs.imagePath = concealCommand.String("i", "image-path", &argparse.Options{
		Required: true,
		Help:     "Path to image you want to conceal a message in",
		Validate: nonEmptyStringValidator,
	})

	concealArgs.passphrase = concealCommand.String("p", "passphrase", &argparse.Options{
		Required: false,
		Help:     "Passphrase to encrypt the message in the image",
		Validate: nonEmptyStringValidator,
	})

	concealArgs.publicKeyPath = concealCommand.String("k", "key-path", &argparse.Options{
		Required: false,
		Help:     "Path to .pem file containing recipient's public key",
		Validate: nonEmptyStringValidator,
	})

	concealArgs.message = concealCommand.String("m", "message", &argparse.Options{
		Required: true,
		Help:     "Message you want to conceal",
		Validate: nonEmptyStringValidator,
	})

	concealArgs.output = concealCommand.String("o", "output", &argparse.Options{
		Required: false,
		Help: "Output path for the image with a concealed message. " +
			"If no output path is provided then the image will be named *filename*.out",
		Validate: nonEmptyStringValidator,
	})

	concealArgs.numBitsPerChannel = concealCommand.Int("n", "num-bits", &argparse.Options{
		Required: false,
		Default:  1,
		Help:     "Number of bits to use per channel value",
		Validate: byteIndexValidator,
	})

	concealArgs.encoding = concealCommand.Selector("e", "encoding", []string{"utf8"}, &argparse.Options{
		Required: false,
		Default:  "utf8",
		Help:     "Encoding to be used for the message",
	})

	concealArgs.numChannels = concealCommand.Int("c", "channels", &argparse.Options{
		Required: false,
		Default:  3,
		Help:     "Number of RGBA channels to use to encode data. 1 channel uses R, 2 channels use RG, 3 channels use RGB, and 4 channels use RGBA",
		Validate: numChannelsValidator,
	})

	concealArgs.verbose = concealCommand.Flag("v", "verbose", &argparse.Options{
		Required: false,
		Default:  false,
		Help:     "Enable verbose",
	})

	return concealCommand, concealArgs
}

func initRevealCommand(parser *argparse.Parser) (*argparse.Command, *RevealArgs) {
	revealArgs := &RevealArgs{}

	revealCommand := parser.NewCommand("reveal", "Reveal a message in an image")

	revealArgs.imagePath = revealCommand.String("i", "image-path", &argparse.Options{
		Required: true,
		Help:     "Path to image with the message you want to reveal",
		Validate: nonEmptyStringValidator,
	})

	revealArgs.passphrase = revealCommand.String("p", "passphrase", &argparse.Options{
		Required: false,
		Help:     "Passphrase to decrypt the message in the image",
		Validate: nonEmptyStringValidator,
	})

	revealArgs.privateKeyPath = revealCommand.String("k", "key-path", &argparse.Options{
		Required: false,
		Help:     "Path to .pem file containing your private key",
		Validate: nonEmptyStringValidator,
	})
	revealArgs.encoding = revealCommand.Selector("e", "encoding", []string{"utf8"}, &argparse.Options{
		Required: false,
		Default:  "utf8",
		Help:     "Choose the encoding that was originally used to conceal your message",
	})

	revealArgs.verbose = revealCommand.Flag("v", "verbose", &argparse.Options{
		Required: false,
		Default:  false,
		Help:     "Enable verbose",
	})

	return revealCommand, revealArgs
}
