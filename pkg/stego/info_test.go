package stego

import (
	"crypto/rand"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog/log"
)

func TestGetInfo(t *testing.T) {
	// Silence logs during tests
	log.Logger = log.Output(io.Discard)

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.png")
	outputPath := filepath.Join(tmpDir, "output.png")

	// Create a standard test image
	img := image.NewNRGBA(image.Rect(0, 0, 512, 512))
	rand.Read(img.Pix)
	f, _ := os.Create(inputPath)
	png.Encode(f, img)
	f.Close()

	tests := []struct {
		name           string
		strategy       string
		channels       int
		bits           int
		compress       bool
		passphrase     string
		expectDataSize bool // Can we expect accurate data size?
	}{
		{
			name:           "LSB Standard No Encryption",
			strategy:       "lsb",
			channels:       3,
			bits:           2,
			compress:       false,
			passphrase:     "",
			expectDataSize: true,
		},
		{
			name:           "LSB Matching Compressed",
			strategy:       "lsb-matching",
			channels:       4,
			bits:           1,
			compress:       true,
			passphrase:     "",
			expectDataSize: true,
		},
		{
			name:           "DCT Standard",
			strategy:       "dct",
			channels:       3, // DCT forces 1
			bits:           1, // DCT forces 1
			compress:       false,
			passphrase:     "",
			expectDataSize: true,
		},
		{
			name:           "LSB Encrypted (Garbage Size Expected)",
			strategy:       "lsb",
			channels:       3,
			bits:           2,
			compress:       false,
			passphrase:     "secret",
			expectDataSize: false, // Size reading depends on seed, which GetInfo lacks
		},
	}

	message := "Test Metadata Analysis"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Conceal data
			err := Conceal(&ConcealArgs{
				ImagePath:         &inputPath,
				Output:            &outputPath,
				Message:           &message,
				Passphrase:        &tt.passphrase,
				NumBitsPerChannel: &tt.bits,
				NumChannels:       &tt.channels,
				Strategy:          &tt.strategy,
				Compress:          &tt.compress,
				Verbose:           new(bool),
				File:              new(string),
				PublicKeyPath:     new(string),
				Encoding:          new(string),
			})
			if err != nil {
				t.Fatalf("Conceal failed: %v", err)
			}

			// Get Info
			info, err := GetInfo(outputPath)
			if err != nil {
				t.Fatalf("GetInfo failed: %v", err)
			}

			// Verify Strategy
			if info.Strategy != tt.strategy {
				t.Errorf("Strategy mismatch: got %s, want %s", info.Strategy, tt.strategy)
			}

			// Verify Compression
			if info.IsCompressed != tt.compress {
				t.Errorf("Compression mismatch: got %v, want %v", info.IsCompressed, tt.compress)
			}

			// Verify Channels/Bits (DCT overrides these to 1/1)
			expectedCh := tt.channels
			expectedBits := tt.bits
			if tt.strategy == "dct" {
				expectedCh = 1
				expectedBits = 1
			}

			if info.Channels != expectedCh {
				t.Errorf("Channels mismatch: got %d, want %d", info.Channels, expectedCh)
			}
			if info.BitDepth != expectedBits {
				t.Errorf("BitDepth mismatch: got %d, want %d", info.BitDepth, expectedBits)
			}

			// Verify DataSize. We can't know the exact size due to overhead (RS, encryption),
			// but for unencrypted data, it should be greater than the original message length.
			if tt.expectDataSize {
				if info.DataSize <= int64(len(message)) {
					t.Errorf("Expected DataSize to be greater than message length, got %d, want > %d", info.DataSize, len(message))
				}
			}
		})
	}
}