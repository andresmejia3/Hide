package main

import (
	"fmt"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	verifyFlags struct {
		Image   string
		Pass    string
		Workers int
	}
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the integrity of a stego image",
	Long:  `Checks if an image contains a valid hidden message and verifies its integrity using Reed-Solomon codes without extracting the full payload.`,
	Run: func(cmd *cobra.Command, args []string) {
		if verifyFlags.Workers < 0 {
			log.Fatal().Msg("number of workers cannot be negative")
		}

		vArgs := &stego.VerifyArgs{
			ImagePath:  &verifyFlags.Image,
			Passphrase: &verifyFlags.Pass,
			Verbose:    &verbose,
			NumWorkers: &verifyFlags.Workers,
		}

		result, err := stego.Verify(vArgs)
		if err != nil {
			log.Fatal().Err(err).Msg("Verification failed")
		}

		fmt.Println("✅ Image verification successful!")
		fmt.Printf("Strategy:         %s\n", result.Strategy)
		fmt.Printf("Message Size:     %d bits\n", result.MessageBits)
		fmt.Printf("Channels Used:    %d\n", result.NumChannels)
		fmt.Printf("Bits Per Channel: %d\n", result.BitsPerChannel)
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(&verifyFlags.Image, "image-path", "i", "", "Path to image (required)")
	verifyCmd.MarkFlagRequired("image-path")
	verifyCmd.Flags().StringVarP(&verifyFlags.Pass, "passphrase", "p", "", "Passphrase used to encrypt (required for correct pixel traversal if used)")
	verifyCmd.Flags().IntVarP(&verifyFlags.Workers, "workers", "w", 0, "Number of workers to use for concurrency (default: number of CPUs)")
}
