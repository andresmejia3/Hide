package main

import (
	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	kBits int
	kOut  string
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate a pair of public and private keys",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Int("bits", kBits).Str("output", kOut).Msg("Generating RSA keys...")
		if err := stego.GenerateRSAKeys(kBits, kOut); err != nil {
			log.Fatal().Err(err).Msg("Error generating keys")
		}
		log.Info().Msg("Keys generated successfully")
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)

	keysCmd.Flags().IntVarP(&kBits, "bits", "b", 2048, "Number of bits for key length")
	keysCmd.Flags().StringVarP(&kOut, "output", "o", "", "Path to directory to save keys (required)")
	keysCmd.MarkFlagRequired("output")
}
