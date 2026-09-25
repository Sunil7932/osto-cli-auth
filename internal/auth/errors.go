package auth

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidCredentials is intentionally vague: the CLI must not reveal
	// whether the username or the password was wrong.
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrSessionExpired      = errors.New("session expired, please log in again")
	ErrInvalidTOTPCode     = errors.New("invalid two factor code")
	ErrChallengeExpired    = errors.New("two factor challenge expired, start the login again")
	ErrTOTPAlreadyEnabled  = errors.New("two factor authentication is already enabled")
	ErrTOTPNotEnabled      = errors.New("two factor authentication is not enabled")
	ErrNoPendingEnrollment = errors.New("no pending two factor enrollment, run enable-2fa first")
)

// AccountLockedError is returned while the lockout window is open.
type AccountLockedError struct {
	Until time.Time
}

func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("account is locked until %s", e.Until.Local().Format("15:04:05"))
}

// RetryAfter is how long the caller has to wait, rounded to whole seconds.
func (e *AccountLockedError) RetryAfter(now time.Time) time.Duration {
	left := e.Until.Sub(now)
	if left < 0 {
		return 0
	}
	return left.Round(time.Second)
}

// CredentialError carries the generic invalid credentials failure plus, when
// the account exists, how many attempts are left before the lockout kicks in.
type CredentialError struct {
	// RemainingAttempts is -1 when the account could not be identified.
	RemainingAttempts int
}

func (e *CredentialError) Error() string { return ErrInvalidCredentials.Error() }

// Unwrap lets callers keep using errors.Is(err, ErrInvalidCredentials).
func (e *CredentialError) Unwrap() error { return ErrInvalidCredentials }

// TOTPError is a rejected one time code. Wrong codes count towards the same
// lockout budget as wrong passwords, hence the remaining attempt count.
type TOTPError struct {
	RemainingAttempts int
}

func (e *TOTPError) Error() string { return ErrInvalidTOTPCode.Error() }

func (e *TOTPError) Unwrap() error { return ErrInvalidTOTPCode }
