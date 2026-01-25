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
	"io/ioutil"
	"os"
	"path/filepath"
)

func createHash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	return encryptWithKey(data, createHash(passphrase))
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

func decrypt(data []byte, passphrase string) ([]byte, error) {
	return decryptWithKey(data, createHash(passphrase))
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
	// Generate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	// Validate Output Directory
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory does not exist: %s", outDir)
	}

	// Save Private Key
	privFile, err := os.Create(filepath.Join(outDir, "private.pem"))
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

	// Generate Public Key
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
	// 1. Load Public Key
	pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
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

	// 2. Generate Random AES Key (32 bytes for AES-256)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	// 3. Encrypt the AES Key with RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return nil, err
	}

	// 4. Encrypt the actual data with the AES Key
	encryptedData, err := encryptWithKey(data, aesKey)
	if err != nil {
		return nil, err
	}

	// 5. Combine: [Length of Encrypted Key (4 bytes)] + [Encrypted Key] + [Encrypted Data]
	// We need the length because RSA key size might vary (2048 vs 4096 bits)
	payload := make([]byte, 4+len(encryptedKey)+len(encryptedData))
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(encryptedKey)))
	copy(payload[4:], encryptedKey)
	copy(payload[4+len(encryptedKey):], encryptedData)

	return payload, nil
}

func decryptRSA(data []byte, privKeyPath string) (plaintext []byte, err error) {
	// 1. Load Private Key
	privKeyBytes, err := ioutil.ReadFile(privKeyPath)
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

	// 2. Parse Payload Structure
	if len(data) < 4 {
		return nil, fmt.Errorf("invalid data: too short")
	}
	keyLen := binary.BigEndian.Uint32(data[0:4])
	if uint32(len(data)) < 4+keyLen {
		return nil, fmt.Errorf("invalid data: malformed key length")
	}

	encryptedKey := data[4 : 4+keyLen]
	encryptedData := data[4+keyLen:]

	// 3. Decrypt AES Key with RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	// 4. Decrypt Data with AES Key
	plaintext, err = decryptWithKey(encryptedData, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}
	return plaintext, nil
}
