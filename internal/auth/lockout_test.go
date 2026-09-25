package auth_test

import (
	"testing"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

func TestLockoutPolicyLocksOnTheConfiguredAttempt(t *testing.T) {
	policy := auth.LockoutPolicy{MaxAttempts: 3, Duration: 5 * time.Minute}
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	user := &domain.User{}

	for attempt := 1; attempt < policy.MaxAttempts; attempt++ {
		if policy.RegisterFailure(user, now) {
			t.Fatalf("attempt %d should not lock the account", attempt)
		}
		if got, want := policy.RemainingAttempts(user), policy.MaxAttempts-attempt; got != want {
			t.Errorf("attempt %d: remaining = %d, want %d", attempt, got, want)
		}
	}

	if !policy.RegisterFailure(user, now) {
		t.Fatal("the final attempt should lock the account")
	}
	if user.LockedUntil == nil || !user.LockedUntil.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("locked until = %v, want %v", user.LockedUntil, now.Add(5*time.Minute))
	}
	// The counter restarts with the lock, so the next window needs the full
	// number of failures again.
	if user.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0 after locking", user.FailedLoginAttempts)
	}
	if !user.IsLocked(now) {
		t.Error("the user should report as locked")
	}
	if user.IsLocked(now.Add(6 * time.Minute)) {
		t.Error("the lock should be over after the configured duration")
	}
}

func TestClearExpiredLock(t *testing.T) {
	policy := auth.LockoutPolicy{MaxAttempts: 3, Duration: 5 * time.Minute}
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	until := now.Add(5 * time.Minute)
	user := &domain.User{LockedUntil: &until, FailedLoginAttempts: 2}

	if policy.ClearExpiredLock(user, now) {
		t.Fatal("a lock that is still open must not be cleared")
	}
	if !policy.ClearExpiredLock(user, until.Add(time.Second)) {
		t.Fatal("an expired lock should be cleared")
	}
	if user.LockedUntil != nil || user.FailedLoginAttempts != 0 {
		t.Fatalf("user = %+v, want the lock state cleared", user)
	}
}

func TestResetReportsWhetherAnythingChanged(t *testing.T) {
	policy := auth.DefaultLockoutPolicy()
	user := &domain.User{}

	if policy.Reset(user) {
		t.Error("resetting a clean user should not report a change")
	}

	user.FailedLoginAttempts = 2
	if !policy.Reset(user) {
		t.Error("resetting a user with failures should report a change")
	}
	if user.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", user.FailedLoginAttempts)
	}
}
