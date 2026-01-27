package stego

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "orig.png")
	stegoPath := filepath.Join(tmpDir, "stego.png")
	heatmapPath := filepath.Join(tmpDir, "heatmap.png")

	// Case 1: Identical Images
	// MSE should be 0, PSNR should be infinite
	img1 := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	saveImage(t, origPath, img1)
	saveImage(t, stegoPath, img1)

	result, err := Analyze(&AnalyzeArgs{
		OriginalPath: &origPath,
		StegoPath:    &stegoPath,
		HeatmapPath:  &heatmapPath,
	})
	if err != nil {
		t.Fatalf("Analyze failed for identical images: %v", err)
	}

	if result.MSE != 0 {
		t.Errorf("Expected MSE 0 for identical images, got %f", result.MSE)
	}
	if !math.IsInf(result.PSNR, 1) {
		t.Errorf("Expected PSNR +Inf for identical images, got %f", result.PSNR)
	}

	// Case 2: Known Difference
	// Change 1 pixel in 1 channel by a value of 10.
	// Image size 10x10 = 100 pixels.
	// MSE = sum((diff)^2) / (pixels * 3)
	// MSE = (10^2) / (100 * 3) = 100 / 300 = 0.333...
	img2 := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	// Set (0,0) to R=10
	img2.Set(0, 0, color.NRGBA{R: 10, G: 0, B: 0, A: 255})
	saveImage(t, stegoPath, img2)

	result, err = Analyze(&AnalyzeArgs{
		OriginalPath: &origPath,
		StegoPath:    &stegoPath,
		HeatmapPath:  &heatmapPath,
	})
	if err != nil {
		t.Fatalf("Analyze failed for modified image: %v", err)
	}

	expectedMSE := 100.0 / 300.0
	if math.Abs(result.MSE-expectedMSE) > 0.0001 {
		t.Errorf("MSE calculation incorrect. Got %f, want %f", result.MSE, expectedMSE)
	}

	// PSNR = 10 * log10(255^2 / MSE)
	expectedPSNR := 10 * math.Log10((255*255)/expectedMSE)
	if math.Abs(result.PSNR-expectedPSNR) > 0.0001 {
		t.Errorf("PSNR calculation incorrect. Got %f, want %f", result.PSNR, expectedPSNR)
	}

	// Verify Heatmap was created
	if _, err := os.Stat(heatmapPath); os.IsNotExist(err) {
		t.Error("Heatmap file was not created")
	}
}

func saveImage(t *testing.T, path string, img image.Image) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create file %s: %v", path, err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("Failed to encode png to %s: %v", path, err)
	}
}
