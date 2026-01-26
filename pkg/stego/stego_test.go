package stego

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndToEndSteganography(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.png")
	outputPath := filepath.Join(tmpDir, "output.png")

	// We need enough pixels to hold the message + header overhead
	img := image.NewNRGBA(image.Rect(0, 0, 100, 99))
	// Fill with some pattern so it's not just zeroes
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}

	f, err := os.Create(inputPath)
	if err != nil {
		t.Fatalf("Failed to create input image: %v", err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("Failed to encode input image: %v", err)
	}
	f.Close()

	message := "This is an integration test message!"
	passphrase := "correct-horse-battery-staple"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "lsb"

	if err := Conceal(&ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string), // Empty string
		Strategy:          &strategy,
	}); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	revealedBytes, err := Reveal(&RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string), // Empty string
		Strategy:       &strategy,
	})
	if err != nil {
		t.Fatalf("Reveal failed: %v", err)
	}

	output := string(revealedBytes)
	if output != message {
		t.Errorf("Revealed message did not match.\nExpected: %q\nGot:      %q", message, output)
	}
}

func TestEndToEndSteganographyRSA(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_rsa.png")
	outputPath := filepath.Join(tmpDir, "output_rsa.png")

	if err := GenerateRSAKeys(2048, tmpDir); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	privKeyPath := filepath.Join(tmpDir, "private.pem")

	img := image.NewNRGBA(image.Rect(0, 0, 100, 99))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	message := "This is a secure RSA message!"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	emptyPass := ""
	strategy := "lsb"

	if err := Conceal(&ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &emptyPass,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     &pubKeyPath,
		Strategy:          &strategy,
	}); err != nil {
		t.Fatalf("Conceal RSA failed: %v", err)
	}

	revealedBytes, err := Reveal(&RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &emptyPass,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: &privKeyPath,
		Strategy:       &strategy,
	})
	if err != nil {
		t.Fatalf("Reveal RSA failed: %v", err)
	}

	output := strings.TrimSpace(string(revealedBytes))
	if output != message {
		t.Errorf("Revealed RSA message did not match.\nExpected: %q\nGot:      %q", message, output)
	}
}

func TestWrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_wrongpass.png")
	outputPath := filepath.Join(tmpDir, "output_wrongpass.png")

	// Create dummy image
	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	message := "Secret"
	passphrase := "correct"
	wrongPass := "wrong"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "lsb"

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
		Strategy:          &strategy,
	}

	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &wrongPass,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string),
		Strategy:       &strategy,
		Writer:         &bytes.Buffer{}, // Discard output
	}

	_, err := Reveal(rArgs) // We expect an error, so the revealed bytes are not needed.

	if err == nil {
		t.Error("Expected error when revealing with wrong password, got nil")
	}
}

func TestEndToEndSteganographyDCT(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_dct.png")
	outputPath := filepath.Join(tmpDir, "output_dct.png")

	// Create dummy image (needs to be large enough for 8x8 blocks)
	// 200x200 = 625 blocks.
	// 200x200 image for DCT blocks.
	img := image.NewNRGBA(image.Rect(0, 0, 200, 200))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	message := "DCT Test"
	passphrase := "pass"
	bits := 1
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "dct"

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
		Strategy:          &strategy,
	}

	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal DCT failed: %v", err)
	}

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string),
		Strategy:       &strategy,
	}

	revealedBytes, err := Reveal(rArgs)
	if err != nil {
		t.Fatalf("Reveal DCT failed: %v", err)
	}

	output := string(revealedBytes)

	if output != message {
		t.Errorf("Revealed DCT message did not match.\nExpected: %q\nGot:      %q", message, output)
	}
}

func TestCapacityExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_small.png")
	outputPath := filepath.Join(tmpDir, "output_small.png")

	// Small image: 10x10 = 100 pixels.
	// Header needs 35 pixels.
	// Remaining 65 pixels.
	// 3 channels * 8 bits = 24 bits/pixel.
	// Capacity approx 65 * 24 = 1560 bits = 195 bytes.
	// Use a small 10x10 image which has a low capacity.
	img := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	// Message larger than capacity (e.g., 1KB)
	message := strings.Repeat("A", 1024)
	passphrase := "pass"
	bits := 8
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "lsb"

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
		Strategy:          &strategy,
	}

	if err := Conceal(cArgs); err == nil {
		t.Error("Expected error for message exceeding capacity, got nil")
	}
}

func TestCorruptedHeader(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_corrupt.png")
	outputPath := filepath.Join(tmpDir, "output_corrupt.png")

	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	message := "Secret"
	passphrase := "pass"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "lsb"

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
		Strategy:          &strategy,
	}

	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	// Corrupt the header (Pixel 0: Bits Per Channel)
	// We set it to 0, which is invalid (must be 1-8)
	// Corrupt the header by setting the bits-per-channel to an invalid value (0).
	imgRaw, err := loadImage(outputPath)
	if err != nil {
		t.Fatalf("Failed to load output image: %v", err)
	}
	outImg := copyImage(imgRaw)
	outImg.Pix[0] = 0
	outImg.Pix[1] = 0
	outImg.Pix[2] = 0
	outImg.Pix[3] = 0

	fOut, _ := os.Create(outputPath)
	png.Encode(fOut, outImg)
	fOut.Close()

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string),
		Strategy:       &strategy,
		Writer:         &bytes.Buffer{},
	}

	if _, err := Reveal(rArgs); err == nil {
		t.Error("Expected error when revealing corrupted header, got nil")
	}
}

func TestLSBMatching(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_lsbm.png")
	outputPath := filepath.Join(tmpDir, "output_lsbm.png")

	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	if _, err := rand.Read(img.Pix); err != nil {
		t.Fatalf("Failed to create random image: %v", err)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	message := "LSB Matching Test"
	passphrase := "pass"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	strategy := "lsb-matching"

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		File:              new(string),
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
		Strategy:          &strategy,
	}

	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string),
		Strategy:       &strategy,
	}

	revealedBytes, err := Reveal(rArgs)
	if err != nil {
		t.Fatalf("Reveal failed: %v", err)
	}

	if string(revealedBytes) != message {
		t.Errorf("Revealed message mismatch. Got %s, want %s", string(revealedBytes), message)
	}
}
