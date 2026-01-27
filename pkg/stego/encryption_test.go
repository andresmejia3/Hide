package stego

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSymmetricEncryption(t *testing.T) {
	passphrase := "supersecret"
	message := []byte("Hello, World!")
	salt := []byte("randomsalt123456")

	encrypted, err := encrypt(message, passphrase, salt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := decrypt(encrypted, passphrase, salt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message does not match original. Got %s, want %s", decrypted, message)
	}
}

func TestRSAEncryption(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateRSAKeys(2048, tmpDir)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	privKeyPath := filepath.Join(tmpDir, "private.pem")

	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Error("Public key file was not created")
	}
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	message := []byte("Secret RSA Message")
	encrypted, err := encryptRSA(message, pubKeyPath)
	if err != nil {
		t.Fatalf("Failed to encrypt with RSA: %v", err)
	}

	decrypted, err := decryptRSA(encrypted, privKeyPath)
	if err != nil {
		t.Fatalf("Failed to decrypt with RSA: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted RSA message does not match. Got %s, want %s", decrypted, message)
	}
}

func TestRSAKeyGenerationError(t *testing.T) {
	// Try to generate keys in a non-existent directory
	if err := GenerateRSAKeys(2048, "/path/to/non/existent/dir/12345"); err == nil {
		t.Error("Expected error when generating keys in invalid directory, got nil")
	}
}
