package stego

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndToEndSteganography(t *testing.T) {
	// 1. Setup paths
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.png")
	outputPath := filepath.Join(tmpDir, "output.png")

	// 2. Create a dummy PNG image (100x99)
	// We need enough pixels to hold the message + header overhead
	img := image.NewNRGBA(image.Rect(0, 0, 100, 99))
	// Fill with some pattern so it's not just zeroes
	for i := 0; i < len(img.Pix); i++ {
		img.Pix[i] = uint8(i % 255)
	}

	f, err := os.Create(inputPath)
	if err != nil {
		t.Fatalf("Failed to create input image: %v", err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("Failed to encode input image: %v", err)
	}
	f.Close()

	// 3. Define Arguments
	message := "This is an integration test message!"
	passphrase := "correct-horse-battery-staple"
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
		PublicKeyPath:     new(string), // Empty string
		Strategy:          &strategy,
	}

	// 4. Run Conceal
	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	// 5. Run Reveal
	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string), // Empty string
		Strategy:       &strategy,
	}

	revealedBytes, err := Reveal(rArgs)

	output := string(revealedBytes)

	if err != nil {
		t.Fatalf("Reveal failed: %v", err)
	}

	// 6. Verify
	if output != message {
		t.Errorf("Revealed message did not match.\nExpected: %q\nGot:      %q", message, output)
	}
}

func TestEndToEndSteganographyRSA(t *testing.T) {
	// 1. Setup paths
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input_rsa.png")
	outputPath := filepath.Join(tmpDir, "output_rsa.png")

	// 2. Generate RSA Keys
	if err := GenerateRSAKeys(2048, tmpDir); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	privKeyPath := filepath.Join(tmpDir, "private.pem")

	// 3. Create dummy image
	img := image.NewNRGBA(image.Rect(0, 0, 100, 99))
	for i := 0; i < len(img.Pix); i++ {
		img.Pix[i] = uint8(i % 255)
	}
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	// 4. Define Arguments
	message := "This is a secure RSA message!"
	bits := 2
	channels := 3
	verbose := false
	encoding := "utf8"
	emptyPass := ""
	strategy := "lsb"

	cArgs := &ConcealArgs{
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
	}

	// 5. Run Conceal
	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal RSA failed: %v", err)
	}

	// 6. Run Reveal
	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &emptyPass,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: &privKeyPath,
		Strategy:       &strategy,
	}

	revealedBytes, err := Reveal(rArgs)
	output := strings.TrimSpace(string(revealedBytes))

	if err != nil {
		t.Fatalf("Reveal RSA failed: %v", err)
	}

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
	}

	// We expect an error, so we don't need the revealed bytes
	_, err := Reveal(rArgs)

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
	img := image.NewNRGBA(image.Rect(0, 0, 200, 200))
	for i := 0; i < len(img.Pix); i++ {
		img.Pix[i] = uint8(i % 255)
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

	rArgs := &RevealArgs{ImagePath: &outputPath, Passphrase: &passphrase, Verbose: &verbose, Encoding: &encoding, PrivateKeyPath: new(string), Strategy: &strategy}

	revealedBytes, err := Reveal(rArgs)
	if err != nil {
		t.Fatalf("Reveal DCT failed: %v", err)
	}

	output := string(revealedBytes)

	if err != nil {
		t.Fatalf("Reveal DCT failed: %v", err)
	}

	if output != message {
		t.Errorf("Revealed DCT message did not match.\nExpected: %q\nGot:      %q", message, output)
	}
}
