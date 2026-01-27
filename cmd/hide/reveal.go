package main

import (
	"os"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	revealFlags struct {
		Image    string
		Pass     string
		Key      string
		Encoding string
		Strategy string
		Out      string
		Workers  int
	}
)

var revealCmd = &cobra.Command{
	Use:   "reveal",
	Short: "Reveal a message in an image",
	Run: func(cmd *cobra.Command, args []string) {
		if revealFlags.Pass != "" && revealFlags.Key != "" {
			log.Fatal().Msg("passphrase and key-path cannot both be provided")
		}
		if revealFlags.Workers < 0 {
			log.Fatal().Msg("number of workers cannot be negative")
		}

		rArgs := &stego.RevealArgs{
			ImagePath:      &revealFlags.Image,
			Passphrase:     &revealFlags.Pass,
			PrivateKeyPath: &revealFlags.Key,
			Encoding:       &revealFlags.Encoding,
			Verbose:        &verbose,
			Strategy:       &revealFlags.Strategy,
			Writer:         os.Stdout,
			NumWorkers:     &revealFlags.Workers,
		}

		if revealFlags.Out != "" {
			f, err := os.Create(revealFlags.Out)
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

	revealCmd.Flags().StringVarP(&revealFlags.Image, "image-path", "i", "", "Path to image (required)")
	revealCmd.MarkFlagRequired("image-path")
	revealCmd.Flags().StringVarP(&revealFlags.Pass, "passphrase", "p", "", "Passphrase to decrypt the message")
	revealCmd.Flags().StringVarP(&revealFlags.Key, "key-path", "k", "", "Path to .pem file containing your private key")
	revealCmd.Flags().StringVarP(&revealFlags.Encoding, "encoding", "e", "utf8", "Encoding used to conceal message")
	revealCmd.Flags().StringVarP(&revealFlags.Strategy, "strategy", "s", "dct", "Steganography strategy: lsb, lsb-matching, dct")
	revealCmd.Flags().StringVarP(&revealFlags.Out, "output", "o", "", "Output path for revealed message (optional)")
	revealCmd.Flags().IntVarP(&revealFlags.Workers, "workers", "w", 0, "Number of workers to use for concurrency (default: number of CPUs)")
}
