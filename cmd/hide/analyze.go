package main

import (
	"fmt"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	aOriginal string
	aStego    string
	aHeatmap  string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze the difference between an original and a stego image",
	Long:  `Calculates PSNR (Peak Signal-to-Noise Ratio) and generates a heatmap image highlighting modified pixels.`,
	Run: func(cmd *cobra.Command, args []string) {
		if aHeatmap == "" {
			aHeatmap = "heatmap.png"
		}

		aArgs := &stego.AnalyzeArgs{
			OriginalPath: &aOriginal,
			StegoPath:    &aStego,
			HeatmapPath:  &aHeatmap,
		}
		result, err := stego.Analyze(aArgs)
		if err != nil {
			log.Fatal().Err(err).Msg("Analysis failed")
		}

		fmt.Printf("Analysis Complete:\n")
		fmt.Printf("------------------\n")
		fmt.Printf("MSE (Mean Squared Error):       %.4f\n", result.MSE)
		fmt.Printf("PSNR (Peak Signal-to-Noise):    %.2f dB\n", result.PSNR)
		fmt.Printf("Heatmap saved to:               %s\n", aHeatmap)
		fmt.Printf("\nInterpretation:\n")
		fmt.Printf(" > 30dB: Good quality (hard to detect visually)\n")
		fmt.Printf(" > 40dB: Excellent quality\n")
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringVarP(&aOriginal, "original", "o", "", "Path to original image (required)")
	analyzeCmd.MarkFlagRequired("original")
	analyzeCmd.Flags().StringVarP(&aStego, "stego", "s", "", "Path to stego image (required)")
	analyzeCmd.MarkFlagRequired("stego")
	analyzeCmd.Flags().StringVarP(&aHeatmap, "heatmap", "d", "heatmap.png", "Output path for the difference heatmap image")
}
