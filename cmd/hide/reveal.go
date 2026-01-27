package main

import (
	"os"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	rImage    string
	rPass     string
	rKey      string
	rEncoding string
	rStrategy string
	rOut      string
	rWorkers  int
)

var revealCmd = &cobra.Command{
	Use:   "reveal",
	Short: "Reveal a message in an image",
	Run: func(cmd *cobra.Command, args []string) {
		if rPass != "" && rKey != "" {
			log.Fatal().Msg("passphrase and key-path cannot both be provided")
		}
		if rWorkers < 0 {
			log.Fatal().Msg("number of workers cannot be negative")
		}

		rArgs := &stego.RevealArgs{
			ImagePath:      &rImage,
			Passphrase:     &rPass,
			PrivateKeyPath: &rKey,
			Encoding:       &rEncoding,
			Verbose:        &verbose,
			Strategy:       &rStrategy,
			Writer:         os.Stdout,
			NumWorkers:     &rWorkers,
		}

		if rOut != "" {
			f, err := os.Create(rOut)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to create output file")
			}
			defer f.Close()
			rArgs.Writer = f
		}

		_, err := stego.Reveal(rArgs)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to reveal message")
		}
		// If writing to stdout, Reveal handles it via rArgs.Writer
	},
}

func init() {
	rootCmd.AddCommand(revealCmd)

	revealCmd.Flags().StringVarP(&rImage, "image-path", "i", "", "Path to image (required)")
	revealCmd.MarkFlagRequired("image-path")
	revealCmd.Flags().StringVarP(&rPass, "passphrase", "p", "", "Passphrase to decrypt the message")
	revealCmd.Flags().StringVarP(&rKey, "key-path", "k", "", "Path to .pem file containing your private key")
	revealCmd.Flags().StringVarP(&rEncoding, "encoding", "e", "utf8", "Encoding used to conceal message")
	revealCmd.Flags().StringVarP(&rStrategy, "strategy", "s", "dct", "Steganography strategy: lsb, lsb-matching, dct")
	revealCmd.Flags().StringVarP(&rOut, "output", "o", "", "Output path for revealed message (optional)")
	revealCmd.Flags().IntVarP(&rWorkers, "workers", "w", 0, "Number of workers to use for concurrency (default: number of CPUs)")
}
