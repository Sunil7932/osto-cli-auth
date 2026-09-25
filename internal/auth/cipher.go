package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// SecretCipher protects values that have to be readable by the application but
// must not be usable straight out of a database dump. TOTP shared secrets are
// the only such value today.
type SecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// AESGCMCipher encrypts with AES-256-GCM. The stored form is
// base64(nonce || ciphertext || tag).
type AESGCMCipher struct {
	aead cipher.AEAD
}

func NewAESGCMCipher(key string) (*AESGCMCipher, error) {
	if len(key) < 16 {
		return nil, errors.New("encryption key must be at least 16 characters")
	}
	// The key material comes from configuration and is not guaranteed to be
	// 32 bytes, so it is stretched with SHA-256 into a full AES-256 key.
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &AESGCMCipher{aead: aead}, nil
}

func (c *AESGCMCipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (c *AESGCMCipher) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("stored secret is truncated")
	}
	plaintext, err := c.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		// Either the ciphertext was tampered with or AUTH_SECRET_KEY changed.
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}
