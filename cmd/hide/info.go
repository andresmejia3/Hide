package main

import (
	"fmt"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info [image_path]",
	Short: "Inspect a stego image and display its metadata header",
	Long:  `Reads the header of a steganographic image to extract metadata such as the encoding strategy, payload size, and compression status.`,
	Args:  cobra.ExactArgs(1), // Requires exactly one argument: the image path
	RunE: func(cmd *cobra.Command, args []string) error {
		imagePath := args[0]

		info, err := stego.GetInfo(imagePath)
		if err != nil {
			return fmt.Errorf("failed to get info from %s: %w", imagePath, err)
		}

		fmt.Println("Stego Header Information:")
		fmt.Println("-------------------------")
		fmt.Printf("Strategy:         %s\n", info.Strategy)
		fmt.Printf("Channels Used:    %d\n", info.Channels)
		fmt.Printf("Bits Per Channel: %d\n", info.BitDepth)
		fmt.Printf("Compressed:       %t\n", info.IsCompressed)
		fmt.Printf("Payload Size:     %d bytes\n", info.DataSize)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
