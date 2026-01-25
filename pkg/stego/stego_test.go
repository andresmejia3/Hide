package stego

import (
	"bytes"
	"image"
	"image/png"
	"io"
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

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string), // Empty string
	}

	// 4. Run Conceal
	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal failed: %v", err)
	}

	// 5. Run Reveal
	// Reveal prints to stdout, so we need to capture it to verify the message
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &passphrase,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: new(string), // Empty string
	}

	err = Reveal(rArgs)

	w.Close()
	os.Stdout = oldStdout // Restore stdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := strings.TrimSpace(buf.String())

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
	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
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

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		Passphrase:        &emptyPass,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     &pubKeyPath,
	}

	// 5. Run Conceal
	if err := Conceal(cArgs); err != nil {
		t.Fatalf("Conceal RSA failed: %v", err)
	}

	// 6. Run Reveal
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rArgs := &RevealArgs{
		ImagePath:      &outputPath,
		Passphrase:     &emptyPass,
		Verbose:        &verbose,
		Encoding:       &encoding,
		PrivateKeyPath: &privKeyPath,
	}

	err := Reveal(rArgs)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := strings.TrimSpace(buf.String())

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
	img := image.NewNRGBA(image.Rect(0, 0, 50, 50))
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

	cArgs := &ConcealArgs{
		ImagePath:         &inputPath,
		Output:            &outputPath,
		Message:           &message,
		Passphrase:        &passphrase,
		NumBitsPerChannel: &bits,
		NumChannels:       &channels,
		Verbose:           &verbose,
		Encoding:          &encoding,
		PublicKeyPath:     new(string),
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
	}

	// Capture stdout to prevent pollution, though we expect error
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Reveal(rArgs)

	w.Close()
	os.Stdout = oldStdout
	io.Copy(io.Discard, r)

	if err == nil {
		t.Error("Expected error when revealing with wrong password, got nil")
	}
}
