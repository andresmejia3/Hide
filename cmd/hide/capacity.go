package main

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"text/tabwriter"

	"github.com/andresmejia3/hide/pkg/stego"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var capacityCmd = &cobra.Command{
	Use:   "capacity [image-path]",
	Short: "Calculate the storage capacity of an image",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		imagePath := args[0]

		f, err := os.Open(imagePath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open image")
		}
		defer f.Close()

		img, _, err := image.Decode(f)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to decode image")
		}

		bounds := img.Bounds()
		w, h := bounds.Max.X, bounds.Max.Y

		wtr := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(wtr, "Strategy\tChannels\tBits/Channel\tCapacity (Bytes)\tCapacity (Bits)")
		fmt.Fprintln(wtr, "--------\t--------\t------------\t----------------\t---------------")

		// LSB Scenarios
		printCap(wtr, w, h, 3, 1, "lsb")
		printCap(wtr, w, h, 3, 2, "lsb")
		printCap(wtr, w, h, 3, 4, "lsb")
		printCap(wtr, w, h, 4, 1, "lsb")

		// DCT Scenario
		printCap(wtr, w, h, 1, 1, "dct")

		wtr.Flush()
	},
}

func printCap(wtr *tabwriter.Writer, w, h, c, b int, s string) {
	bits := stego.GetCapacity(w, h, c, b, s)
	bytes := bits / 8
	fmt.Fprintf(wtr, "%s\t%d\t%d\t%d\t%d\n", s, c, b, bytes, bits)
}

func init() {
	rootCmd.AddCommand(capacityCmd)
}
