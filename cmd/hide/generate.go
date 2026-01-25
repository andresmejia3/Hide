package main

import (
	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	gBytes int
	gOut   string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a pair of public and private keys",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Int("bits", gBytes).Str("output", gOut).Msg("Generating RSA keys...")
		if err := stego.GenerateRSAKeys(gBytes, gOut); err != nil {
			log.Fatal().Err(err).Msg("Error generating keys")
		}
		log.Info().Msg("Keys generated successfully")
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().IntVarP(&gBytes, "num-bytes", "n", 2048, "Number of bits for key length")
	generateCmd.Flags().StringVarP(&gOut, "output", "o", "", "Path to directory to save keys (required)")
	generateCmd.MarkFlagRequired("output")
}
