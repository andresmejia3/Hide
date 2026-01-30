package main

import (
	"os"
	"path/filepath"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	concealFlags struct {
		Image    string
		Pass     string
		Key      string
		Msg      string
		File     string
		Out      string
		Bits     int
		Encoding string
		Chan     int
		Strategy string
		Workers  int
		DryRun   bool
		Compress bool
	}
)

var concealCmd = &cobra.Command{
	Use:   "conceal",
	Short: "Conceal a message in an image",
	Run: func(cmd *cobra.Command, args []string) {
		if concealFlags.Pass != "" && concealFlags.Key != "" {
			log.Fatal().Msg("passphrase and key-path cannot both be provided")
		}
		if concealFlags.Msg != "" && concealFlags.File != "" {
			log.Fatal().Msg("message and file flags cannot both be provided; file takes precedence")
		}
		if concealFlags.Bits < 0 || concealFlags.Bits > 8 {
			log.Fatal().Msg("maximum number of bits to use per channel is 8")
		}
		if concealFlags.Chan < 1 || concealFlags.Chan > 4 {
			log.Fatal().Msg("channels argument can only be 1, 2, 3, or 4")
		}
		if concealFlags.Workers < 0 {
			log.Fatal().Msg("number of workers cannot be negative")
		}

		// Default output handling
		if concealFlags.Out == "" {
			outputDir := "output"
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				log.Fatal().Err(err).Msg("Failed to create default output directory")
			}
			concealFlags.Out = filepath.Join(outputDir, "hidden.png")
		} else {
			// Ensure the directory for the provided output path exists
			if err := os.MkdirAll(filepath.Dir(concealFlags.Out), 0755); err != nil {
				log.Fatal().Err(err).Msg("Failed to create output directory")
			}
		}

		cArgs := &stego.ConcealArgs{
			ImagePath:         &concealFlags.Image,
			Passphrase:        &concealFlags.Pass,
			PublicKeyPath:     &concealFlags.Key,
			Message:           &concealFlags.Msg,
			File:              &concealFlags.File,
			Output:            &concealFlags.Out,
			NumBitsPerChannel: &concealFlags.Bits,
			Encoding:          &concealFlags.Encoding,
			NumChannels:       &concealFlags.Chan,
			Verbose:           &verbose,
			Strategy:          &concealFlags.Strategy,
			NumWorkers:        &concealFlags.Workers,
			DryRun:            &concealFlags.DryRun,
			Compress:          &concealFlags.Compress,
		}

		if err := stego.Conceal(cArgs); err != nil {
			log.Fatal().Err(err).Msg("Failed to conceal message")
		}
	},
}

func init() {
	rootCmd.AddCommand(concealCmd)

	concealCmd.Flags().StringVarP(&concealFlags.Image, "image-path", "i", "", "Path to image (required)")
	concealCmd.MarkFlagRequired("image-path")
	concealCmd.Flags().StringVarP(&concealFlags.Pass, "passphrase", "p", "", "Passphrase to encrypt the message")
	concealCmd.Flags().StringVarP(&concealFlags.Key, "key-path", "k", "", "Path to .pem file containing recipient's public key")
	concealCmd.Flags().StringVarP(&concealFlags.Msg, "message", "m", "", "Message you want to conceal (required)")
	concealCmd.Flags().StringVarP(&concealFlags.File, "file", "f", "", "Path to file to conceal (overrides message). Use '-' for stdin.")
	concealCmd.Flags().StringVarP(&concealFlags.Out, "output", "o", "", "Output path for the image")
	concealCmd.Flags().IntVarP(&concealFlags.Bits, "num-bits", "n", 1, "Number of bits to use per channel value")
	concealCmd.Flags().StringVarP(&concealFlags.Encoding, "encoding", "e", "utf8", "Encoding to be used for the message")
	concealCmd.Flags().IntVarP(&concealFlags.Chan, "channels", "c", 3, "Number of RGBA channels to use (1-4)")
	concealCmd.Flags().StringVarP(&concealFlags.Strategy, "strategy", "s", "dct", "Steganography strategy: lsb, lsb-matching, dct")
	concealCmd.Flags().IntVarP(&concealFlags.Workers, "workers", "w", 0, "Number of workers to use for concurrency (default: number of CPUs)")
	concealCmd.Flags().BoolVar(&concealFlags.DryRun, "dry-run", false, "Check if the message fits without encoding")
	concealCmd.Flags().BoolVarP(&concealFlags.Compress, "compress", "z", true, "Compress data before embedding to save space")
}
