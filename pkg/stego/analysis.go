package stego

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
)

// AnalysisResult holds metrics about the comparison between two images.
type AnalysisResult struct {
	MSE  float64 // Mean Squared Error
	PSNR float64 // Peak Signal-to-Noise Ratio (dB)
}

// Analyze compares an original image with a stego image.
// It returns metrics and generates a difference "heatmap" image.
func Analyze(args *AnalyzeArgs) (*AnalysisResult, error) {
	fmt.Fprintln(os.Stderr, " 📂 Loading images...")
	img1Raw, err := loadImage(*args.OriginalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load original: %v", err)
	}
	img2Raw, err := loadImage(*args.StegoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load stego image: %v", err)
	}

	// Convert both to NRGBA for consistent pixel access
	img1 := copyImage(img1Raw)
	img2 := copyImage(img2Raw)

	bounds := img1.Bounds()
	if bounds != img2.Bounds() {
		return nil, fmt.Errorf("image dimensions do not match: %v vs %v", bounds, img2.Bounds())
	}

	width, height := bounds.Max.X, bounds.Max.Y
	var sumSquaredError float64
	heatmap := image.NewNRGBA(bounds)

	bar := progressbar.NewOptions(
		width*height,
		progressbar.OptionSetDescription(" 📊 Analyzing"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)

	// Iterate over pixels to calculate MSE and build heatmap
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			bar.Add(1)
			p1 := img1.PixOffset(x, y)
			p2 := img2.PixOffset(x, y)

			var diffSum float64
			isModified := false

			// Compare R, G, B channels (ignore Alpha for MSE usually, but check for diffs)
			for i := 0; i < 3; i++ {
				v1 := float64(img1.Pix[p1+i])
				v2 := float64(img2.Pix[p2+i])
				diff := v1 - v2
				sumSquaredError += diff * diff
				diffSum += math.Abs(diff)

				if img1.Pix[p1+i] != img2.Pix[p2+i] {
					isModified = true
				}
			}

			// Heatmap coloring:
			// Black = No change
			// Green = Slight change
			// Red = Major change
			if isModified {
				// Amplify difference for visibility.
				// A difference of 1 becomes 50 brightness.
				intensity := uint8(math.Min(255, diffSum*50))
				heatmap.Set(x, y, color.NRGBA{R: intensity, G: 255 - intensity, B: 0, A: 255})
			} else {
				heatmap.Set(x, y, color.NRGBA{R: 0, G: 0, B: 0, A: 255})
			}
		}
	}

	totalPixels := float64(width * height)
	mse := sumSquaredError / (totalPixels * 3.0) // Average per channel per pixel
	psnr := 10 * math.Log10((255*255)/mse)

	// Save heatmap
	f, err := os.Create(*args.HeatmapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create heatmap file: %v", err)
	}
	defer f.Close()
	png.Encode(f, heatmap)

	fmt.Fprintln(os.Stderr, " ✨ Done!")

	return &AnalysisResult{MSE: mse, PSNR: psnr}, nil
}
