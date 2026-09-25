package auth_test

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

func TestBcryptHasherRoundTrip(t *testing.T) {
	hasher, err := auth.NewBcryptHasher(4)
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}

	hash, err := hasher.Hash("correct-horse-7")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "correct-horse-7" {
		t.Fatal("the hash must not be the password")
	}
	if err := hasher.Verify(hash, "correct-horse-7"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := hasher.Verify(hash, "correct-horse-8"); !errors.Is(err, auth.ErrPasswordMismatch) {
		t.Fatalf("err = %v, want ErrPasswordMismatch", err)
	}
}

func TestBcryptHasherSaltsEveryHash(t *testing.T) {
	hasher, _ := auth.NewBcryptHasher(4)

	first, _ := hasher.Hash("same-password-1")
	second, _ := hasher.Hash("same-password-1")

	if first == second {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestBcryptHasherRejectsUnsupportedCost(t *testing.T) {
	if _, err := auth.NewBcryptHasher(bcrypt.MinCost - 1); err == nil {
		t.Error("expected an error for a cost below the minimum")
	}
	if _, err := auth.NewBcryptHasher(bcrypt.MaxCost + 1); err == nil {
		t.Error("expected an error for a cost above the maximum")
	}
}

func TestNeedsRehashFollowsTheConfiguredCost(t *testing.T) {
	cheap, _ := auth.NewBcryptHasher(4)
	expensive, _ := auth.NewBcryptHasher(6)

	hash, err := cheap.Hash("some-password-1")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if cheap.NeedsRehash(hash) {
		t.Error("a hash at the current cost does not need a rehash")
	}
	if !expensive.NeedsRehash(hash) {
		t.Error("a hash below the current cost should be upgraded")
	}
	if !expensive.NeedsRehash("not-a-bcrypt-hash") {
		t.Error("an unreadable hash should be replaced")
	}
}

func TestPasswordPolicy(t *testing.T) {
	policy := auth.PasswordPolicy{MinLength: 10, MaxLength: 72}

	valid := []string{
		"T0rnado-Pickle!",
		"a-very-long-passphrase-1",
		"9characters!!",
	}
	for _, password := range valid {
		if err := policy.Validate("alice", password); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", password, err)
		}
	}

	invalid := map[string]string{
		"too short":             "Ab3!x",
		"no digit or symbol":    "onlylettershere",
		"whitespace only":       "              ",
		"contains the username": "alice-secret-1",
		"common password":       "password123",
	}
	for name, password := range invalid {
		t.Run(name, func(t *testing.T) {
			err := policy.Validate("alice", password)
			if err == nil {
				t.Fatalf("Validate(%q) = nil, want a validation error", password)
			}
			if !domain.IsValidation(err) {
				t.Fatalf("err = %v, want a validation error", err)
			}
		})
	}
}

// bcrypt ignores input past 72 bytes, so the policy has to reject it instead of
// silently accepting a password whose tail does not matter.
func TestPasswordPolicyRejectsOverlongPasswords(t *testing.T) {
	policy := auth.PasswordPolicy{MinLength: 10, MaxLength: 72}

	err := policy.Validate("alice", strings.Repeat("a1", 40))
	if !domain.IsValidation(err) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if !strings.Contains(err.Error(), "72") {
		t.Errorf("error %q should mention the 72 byte limit", err)
	}
}
