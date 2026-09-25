package auth

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// ErrPasswordMismatch is returned by PasswordHasher.Verify when the password
// does not match the stored hash.
var ErrPasswordMismatch = errors.New("password does not match")

// PasswordHasher abstracts the hashing algorithm. bcrypt is what ships today;
// keeping it behind an interface means a future argon2id implementation only
// has to satisfy these three methods.
type PasswordHasher interface {
	Hash(plain string) (string, error)
	Verify(hash, plain string) error
	// NeedsRehash reports whether an existing hash was produced with weaker
	// parameters than the ones currently configured.
	NeedsRehash(hash string) bool
}

// BcryptHasher is the default PasswordHasher.
type BcryptHasher struct {
	cost int
}

func NewBcryptHasher(cost int) (*BcryptHasher, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost %d is outside the supported range %d-%d", cost, bcrypt.MinCost, bcrypt.MaxCost)
	}
	return &BcryptHasher{cost: cost}, nil
}

func (h *BcryptHasher) Hash(plain string) (string, error) {
	digest, err := bcrypt.GenerateFromPassword([]byte(plain), h.cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(digest), nil
}

func (h *BcryptHasher) Verify(hash, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return ErrPasswordMismatch
	default:
		return fmt.Errorf("compare password: %w", err)
	}
}

func (h *BcryptHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		// An unreadable hash is worth replacing on the next successful login.
		return true
	}
	return cost < h.cost
}

// PasswordPolicy is the set of rules a new password has to satisfy.
type PasswordPolicy struct {
	MinLength int
	MaxLength int
}

// DefaultPasswordPolicy mirrors the defaults in config.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 10, MaxLength: 72}
}

// commonPasswords is deliberately short. A full breach corpus belongs in a
// service of its own; this only stops the most embarrassing choices.
var commonPasswords = map[string]struct{}{
	"password":    {},
	"password1":   {},
	"password123": {},
	"12345678":    {},
	"123456789":   {},
	"1234567890":  {},
	"qwerty123":   {},
	"letmein123":  {},
	"iloveyou123": {},
	"admin123":    {},
	"welcome123":  {},
	"changeme":    {},
}

// Validate checks a candidate password against the policy. The username is
// passed in so that "alice / alice2024" style passwords can be rejected.
func (p PasswordPolicy) Validate(username, password string) error {
	fail := func(msg string) error {
		return &domain.ValidationError{Field: "password", Message: msg}
	}

	// bcrypt works on bytes, so the length limits are measured in bytes too.
	if len(password) < p.MinLength {
		return fail(fmt.Sprintf("must be at least %d characters long", p.MinLength))
	}
	if len(password) > p.MaxLength {
		return fail(fmt.Sprintf("must be at most %d bytes long (bcrypt ignores anything beyond that)", p.MaxLength))
	}
	if strings.TrimSpace(password) == "" {
		return fail("must not be only whitespace")
	}

	var hasLetter, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if !hasLetter || !(hasDigit || hasSymbol) {
		return fail("must mix letters with at least one digit or symbol")
	}

	lower := strings.ToLower(password)
	if _, ok := commonPasswords[lower]; ok {
		return fail("is too common, pick something less guessable")
	}
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return fail("must not contain the username")
	}

	return nil
}
