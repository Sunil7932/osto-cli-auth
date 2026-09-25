package auth

import (
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// LockoutPolicy throttles credential guessing by locking an account for a
// while once the failure counter reaches MaxAttempts.
type LockoutPolicy struct {
	MaxAttempts int
	Duration    time.Duration
}

func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{MaxAttempts: 5, Duration: 15 * time.Minute}
}

// RegisterFailure records one failed attempt on the user and reports whether
// that attempt tripped the lock. The caller is responsible for persisting the
// user afterwards.
func (p LockoutPolicy) RegisterFailure(user *domain.User, now time.Time) bool {
	user.FailedLoginAttempts++
	if user.FailedLoginAttempts < p.MaxAttempts {
		return false
	}

	until := now.Add(p.Duration)
	user.LockedUntil = &until
	// The counter restarts with the lock so the next window needs another
	// MaxAttempts failures rather than locking on the first mistake.
	user.FailedLoginAttempts = 0
	return true
}

// ClearExpiredLock drops a lock whose window has passed. It returns true when
// the user record changed and has to be written back.
func (p LockoutPolicy) ClearExpiredLock(user *domain.User, now time.Time) bool {
	if user.LockedUntil == nil || user.LockedUntil.After(now) {
		return false
	}
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	return true
}

// Reset clears the failure state after a successful authentication.
func (p LockoutPolicy) Reset(user *domain.User) bool {
	if user.FailedLoginAttempts == 0 && user.LockedUntil == nil {
		return false
	}
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	return true
}

// RemainingAttempts is how many more failures the account tolerates before it
// gets locked.
func (p LockoutPolicy) RemainingAttempts(user *domain.User) int {
	left := p.MaxAttempts - user.FailedLoginAttempts
	if left < 0 {
		return 0
	}
	return left
}
