package stego

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

func createHash(key string, salt []byte) []byte {
	// Use the standard PBKDF2 key derivation function.
	// 32 bytes for AES-256.
	return pbkdf2.Key([]byte(key), salt, 100000, 32, sha256.New)
}

func encrypt(data []byte, passphrase string, salt []byte) ([]byte, error) {
	return encryptWithKey(data, createHash(passphrase, salt))
}

func encryptWithKey(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encryption error: failed to create GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string, salt []byte) ([]byte, error) {
	return decryptWithKey(data, createHash(passphrase, salt))
}

func decryptWithKey(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func GenerateRSAKeys(bits int, outDir string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory does not exist: %s", outDir)
	}

	// Use 0600 permissions to ensure only the owner can read the private key.
	privFile, err := os.OpenFile(filepath.Join(outDir, "private.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	if err := pem.Encode(privFile, privBlock); err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey
	pubFile, err := os.Create(filepath.Join(outDir, "public.pem"))
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return err
	}

	return nil
}

func encryptRSA(data []byte, pubKeyPath string) ([]byte, error) {
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type RSA")
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encryptWithKey(data, aesKey)
	if err != nil {
		return nil, err
	}

	// Format: [Key Length (4 bytes)] + [Encrypted Key] + [Encrypted Data]
	// We need the length because RSA key size might vary (2048 vs 4096 bits)
	payload := make([]byte, 4+len(encryptedKey)+len(encryptedData))
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(encryptedKey)))
	copy(payload[4:], encryptedKey)
	copy(payload[4+len(encryptedKey):], encryptedData)

	return payload, nil
}

func decryptRSA(data []byte, privKeyPath string) (plaintext []byte, err error) {
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("invalid data: too short")
	}
	keyLen := binary.BigEndian.Uint32(data[0:4])
	if uint32(len(data)) < 4+keyLen {
		return nil, fmt.Errorf("invalid data: malformed key length")
	}

	encryptedKey := data[4 : 4+keyLen]
	encryptedData := data[4+keyLen:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	plaintext, err = decryptWithKey(encryptedData, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}
	return plaintext, nil
}

func getSeed(passphrase string) int64 {
	if passphrase == "" {
		return 0
	}
	hash := sha256.Sum256([]byte(passphrase))
	return int64(binary.BigEndian.Uint64(hash[:8]))
}
