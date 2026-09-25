package auth_test

import (
	"strings"
	"testing"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
)

func TestAESGCMCipherRoundTrip(t *testing.T) {
	cipher, err := auth.NewAESGCMCipher("unit-test-encryption-key")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	encrypted, err := cipher.Encrypt(totpSecret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if strings.Contains(encrypted, totpSecret) {
		t.Fatal("the ciphertext still contains the plaintext")
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != totpSecret {
		t.Fatalf("decrypted = %q, want %q", decrypted, totpSecret)
	}
}

func TestAESGCMCipherUsesAFreshNonce(t *testing.T) {
	cipher, _ := auth.NewAESGCMCipher("unit-test-encryption-key")

	first, _ := cipher.Encrypt(totpSecret)
	second, _ := cipher.Encrypt(totpSecret)

	if first == second {
		t.Fatal("encrypting twice must not produce identical ciphertext")
	}
}

func TestAESGCMCipherDetectsTampering(t *testing.T) {
	cipher, _ := auth.NewAESGCMCipher("unit-test-encryption-key")
	encrypted, _ := cipher.Encrypt(totpSecret)

	tampered := []byte(encrypted)
	// Flip a character in the middle, keeping the base64 alphabet intact.
	middle := len(tampered) / 2
	if tampered[middle] == 'A' {
		tampered[middle] = 'B'
	} else {
		tampered[middle] = 'A'
	}

	if _, err := cipher.Decrypt(string(tampered)); err == nil {
		t.Fatal("expected modified ciphertext to be rejected")
	}
}

func TestAESGCMCipherRejectsAnotherKey(t *testing.T) {
	original, _ := auth.NewAESGCMCipher("unit-test-encryption-key")
	other, _ := auth.NewAESGCMCipher("a-completely-different-key")

	encrypted, _ := original.Encrypt(totpSecret)

	if _, err := other.Decrypt(encrypted); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestAESGCMCipherRequiresAReasonableKey(t *testing.T) {
	if _, err := auth.NewAESGCMCipher("short"); err == nil {
		t.Fatal("expected a short key to be rejected")
	}
}

func TestAESGCMCipherPassesEmptyValuesThrough(t *testing.T) {
	cipher, _ := auth.NewAESGCMCipher("unit-test-encryption-key")

	encrypted, err := cipher.Encrypt("")
	if err != nil || encrypted != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v, want empty and nil", encrypted, err)
	}
	decrypted, err := cipher.Decrypt("")
	if err != nil || decrypted != "" {
		t.Fatalf("Decrypt(\"\") = %q, %v, want empty and nil", decrypted, err)
	}
}
