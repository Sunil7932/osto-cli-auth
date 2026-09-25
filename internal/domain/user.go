package domain

import (
	"strings"
	"time"
	"unicode"
)

// User is the persisted account record. Everything security related about an
// account lives here: the password hash, the TOTP enrollment and the failed
// login counters used by the lockout policy.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	// TOTPSecret holds the base32 shared secret, encrypted before it reaches
	// the database. It is populated while an enrollment is pending and stays
	// populated once 2FA is confirmed.
	TOTPSecret          string
	TOTPEnabled         bool
	TOTPConfirmedAt     *time.Time
	FailedLoginAttempts int
	LockedUntil         *time.Time
	LastLoginAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// IsLocked reports whether the lockout window is still open at now.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// HasPendingTOTPEnrollment is true when a secret was generated but the user
// never proved they could read a code from it.
func (u *User) HasPendingTOTPEnrollment() bool {
	return u.TOTPSecret != "" && !u.TOTPEnabled
}

// NormalizeUsername folds the username so that "Alice" and "alice" are the
// same account. The database holds the normalised form.
func NormalizeUsername(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// UsernameRules are the limits advertised to the user when validation fails.
const (
	UsernameMinLength = 3
	UsernameMaxLength = 32
)

// ValidateUsername keeps usernames to a predictable character set. Allowing
// arbitrary unicode here would make impersonation through look-alike
// characters too easy.
func ValidateUsername(username string) error {
	if len(username) < UsernameMinLength || len(username) > UsernameMaxLength {
		return &ValidationError{
			Field:   "username",
			Message: "must be between 3 and 32 characters",
		}
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case unicode.IsDigit(r):
		case r == '.' || r == '_' || r == '-':
		default:
			return &ValidationError{
				Field:   "username",
				Message: "may only contain letters, digits, dot, underscore and hyphen",
			}
		}
	}
	return nil
}
