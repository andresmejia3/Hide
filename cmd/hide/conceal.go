package main

import (
	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cImage    string
	cPass     string
	cKey      string
	cMsg      string
	cFile     string
	cOut      string
	cBits     int
	cEncoding string
	cChan     int
	cStrategy string
)

var concealCmd = &cobra.Command{
	Use:   "conceal",
	Short: "Conceal a message in an image",
	Run: func(cmd *cobra.Command, args []string) {
		if cPass != "" && cKey != "" {
			log.Fatal().Msg("passphrase and key-path cannot both be provided")
		}
		if cMsg != "" && cFile != "" {
			log.Fatal().Msg("message and file flags cannot both be provided; file takes precedence")
		}
		if cBits < 0 || cBits > 8 {
			log.Fatal().Msg("maximum number of bits to use per channel is 8")
		}
		if cChan < 1 || cChan > 4 {
			log.Fatal().Msg("channels argument can only be 1, 2, 3, or 4")
		}

		cArgs := &stego.ConcealArgs{
			ImagePath:         &cImage,
			Passphrase:        &cPass,
			PublicKeyPath:     &cKey,
			Message:           &cMsg,
			File:              &cFile,
			Output:            &cOut,
			NumBitsPerChannel: &cBits,
			Encoding:          &cEncoding,
			NumChannels:       &cChan,
			Verbose:           &verbose,
			Strategy:          &cStrategy,
		}

		if err := stego.Conceal(cArgs); err != nil {
			log.Fatal().Err(err).Msg("Failed to conceal message")
		}
	},
}

func init() {
	rootCmd.AddCommand(concealCmd)

	concealCmd.Flags().StringVarP(&cImage, "image-path", "i", "", "Path to image (required)")
	concealCmd.MarkFlagRequired("image-path")
	concealCmd.Flags().StringVarP(&cPass, "passphrase", "p", "", "Passphrase to encrypt the message")
	concealCmd.Flags().StringVarP(&cKey, "key-path", "k", "", "Path to .pem file containing recipient's public key")
	concealCmd.Flags().StringVarP(&cMsg, "message", "m", "", "Message you want to conceal (required)")
	concealCmd.Flags().StringVarP(&cFile, "file", "f", "", "Path to file to conceal (overrides message)")
	concealCmd.Flags().StringVarP(&cOut, "output", "o", "", "Output path for the image")
	concealCmd.Flags().IntVarP(&cBits, "num-bits", "n", 1, "Number of bits to use per channel value")
	concealCmd.Flags().StringVarP(&cEncoding, "encoding", "e", "utf8", "Encoding to be used for the message")
	concealCmd.Flags().IntVarP(&cChan, "channels", "c", 3, "Number of RGBA channels to use (1-4)")
	concealCmd.Flags().StringVarP(&cStrategy, "strategy", "s", "dct", "Steganography strategy: lsb, lsb-matching, dct")
}
