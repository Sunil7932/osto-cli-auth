package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
	"github.com/Sunil7932/cli-login-2fa/internal/storage/memory"
)

const (
	testPassword = "T0rnado-Pickle!"
	validCode    = "123456"
	totpSecret   = "JBSWY3DPEHPK3PXP"
)

// stubTOTP stands in for the authenticator app: one secret, one code that works.
type stubTOTP struct {
	accepted string
}

func (s *stubTOTP) Enroll(accountName string) (auth.Enrollment, error) {
	return auth.Enrollment{
		Secret: totpSecret,
		URI:    "otpauth://totp/test:" + accountName + "?secret=" + totpSecret,
	}, nil
}

func (s *stubTOTP) Verify(secret, code string, _ time.Time) bool {
	return secret == totpSecret && code == s.accepted
}

type fixture struct {
	t       *testing.T
	service *auth.Service
	store   *memory.Store
	clock   *clock.Fake
	totp    *stubTOTP
}

func newFixture(t *testing.T, opts ...auth.Option) *fixture {
	t.Helper()

	store := memory.NewStore()
	fake := clock.NewFake(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	totp := &stubTOTP{accepted: validCode}

	// Cost 4 keeps the suite fast; production runs at 12.
	hasher, err := auth.NewBcryptHasher(4)
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	cipher, err := auth.NewAESGCMCipher("unit-test-encryption-key")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	defaults := []auth.Option{
		auth.WithLockoutPolicy(auth.LockoutPolicy{MaxAttempts: 3, Duration: 10 * time.Minute}),
		auth.WithSessionWindow(15*time.Minute, time.Hour),
		auth.WithChallengeTTL(2 * time.Minute),
	}

	service, err := auth.NewService(auth.Dependencies{
		Users:      store.Users(),
		Sessions:   store.Sessions(),
		Events:     store.Events(),
		Tx:         store.TxManager(),
		Hasher:     hasher,
		TOTP:       totp,
		Cipher:     cipher,
		Challenges: auth.NewMemoryChallengeStore(fake),
		Clock:      fake,
	}, append(defaults, opts...)...)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	return &fixture{t: t, service: service, store: store, clock: fake, totp: totp}
}

func (f *fixture) register(username, password string) *domain.User {
	f.t.Helper()
	user, err := f.service.Register(context.Background(), username, password)
	if err != nil {
		f.t.Fatalf("register %s: %v", username, err)
	}
	return user
}

func (f *fixture) login(username, password string) *auth.Result {
	f.t.Helper()
	result, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username:   username,
		Password:   password,
		ClientInfo: "unit-test",
	})
	if err != nil {
		f.t.Fatalf("login %s: %v", username, err)
	}
	return result
}

func (f *fixture) reload(id int64) *domain.User {
	f.t.Helper()
	user, err := f.store.Users().FindByID(context.Background(), id)
	if err != nil {
		f.t.Fatalf("reload user: %v", err)
	}
	return user
}

func (f *fixture) hasEvent(eventType domain.EventType) bool {
	for _, event := range f.store.AllEvents() {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func TestRegisterNormalisesUsernameAndRecordsEvent(t *testing.T) {
	f := newFixture(t)

	user := f.register("  Alice  ", testPassword)

	if user.Username != "alice" {
		t.Errorf("username = %q, want %q", user.Username, "alice")
	}
	if user.PasswordHash == testPassword || !strings.HasPrefix(user.PasswordHash, "$2") {
		t.Errorf("password does not look bcrypt hashed: %q", user.PasswordHash)
	}
	if user.TOTPEnabled {
		t.Error("two factor should be off for a fresh account")
	}
	if !f.hasEvent(domain.EventRegistered) {
		t.Error("expected a registered event in the audit trail")
	}
}

func TestRegisterRejectsDuplicateUsernameRegardlessOfCase(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)

	_, err := f.service.Register(context.Background(), "ALICE", testPassword)
	if !errors.Is(err, domain.ErrUsernameTaken) {
		t.Fatalf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestRegisterValidatesInput(t *testing.T) {
	f := newFixture(t)

	cases := map[string]struct{ username, password string }{
		"short username":         {"ab", testPassword},
		"illegal characters":     {"alice bob", testPassword},
		"short password":         {"alice", "abc1!"},
		"password without digit": {"alice", "onlylettershere"},
		"password with username": {"alice", "alice-password-1"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.service.Register(context.Background(), tc.username, tc.password)
			if !domain.IsValidation(err) {
				t.Fatalf("err = %v, want a validation error", err)
			}
		})
	}
}

func TestLoginIssuesSessionAndReportsPreviousLogin(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)

	first := f.login("alice", testPassword)
	if first.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want authenticated", first.Status)
	}
	if first.Token == "" {
		t.Fatal("expected a session token")
	}
	if first.PreviousLoginAt != nil {
		t.Errorf("previous login = %v, want nil on the first login", first.PreviousLoginAt)
	}
	if first.Session.TokenHash == first.Token {
		t.Error("the stored session must hold a hash, not the raw token")
	}
	if want := f.clock.Now().Add(15 * time.Minute); !first.Session.IdleExpiresAt.Equal(want) {
		t.Errorf("idle expiry = %v, want %v", first.Session.IdleExpiresAt, want)
	}

	f.clock.Advance(time.Minute)
	second := f.login("alice", testPassword)
	if second.PreviousLoginAt == nil {
		t.Fatal("second login should report the first one")
	}
	if got := f.reload(user.ID).LastLoginAt; got == nil || !got.Equal(f.clock.Now()) {
		t.Errorf("last login = %v, want %v", got, f.clock.Now())
	}
}

func TestLoginWithUnknownUsernameGivesNoHint(t *testing.T) {
	f := newFixture(t)

	_, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "nobody",
		Password: testPassword,
	})

	var credErr *auth.CredentialError
	if !errors.As(err, &credErr) {
		t.Fatalf("err = %v, want a CredentialError", err)
	}
	if credErr.RemainingAttempts != -1 {
		t.Errorf("remaining attempts = %d, want -1 for an unknown account", credErr.RemainingAttempts)
	}
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Error("the error should still match ErrInvalidCredentials")
	}
}

func TestLoginLocksAccountAfterConfiguredFailures(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
			Username: "alice",
			Password: "wrong-password-1",
		})
		var credErr *auth.CredentialError
		if !errors.As(err, &credErr) {
			t.Fatalf("attempt %d: err = %v, want a CredentialError", attempt, err)
		}
		if want := 3 - attempt; credErr.RemainingAttempts != want {
			t.Errorf("attempt %d: remaining = %d, want %d", attempt, credErr.RemainingAttempts, want)
		}
	}

	_, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "alice",
		Password: "wrong-password-1",
	})
	var locked *auth.AccountLockedError
	if !errors.As(err, &locked) {
		t.Fatalf("third failure: err = %v, want AccountLockedError", err)
	}
	if want := f.clock.Now().Add(10 * time.Minute); !locked.Until.Equal(want) {
		t.Errorf("locked until %v, want %v", locked.Until, want)
	}
	if !f.hasEvent(domain.EventAccountLocked) {
		t.Error("expected an account_locked audit event")
	}

	// Even the right password is refused while the lock is open.
	_, err = f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "alice",
		Password: testPassword,
	})
	if !errors.As(err, &locked) {
		t.Fatalf("during lockout: err = %v, want AccountLockedError", err)
	}

	f.clock.Advance(11 * time.Minute)
	if _, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "alice",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("after the lockout window: %v", err)
	}
	if reloaded := f.reload(user.ID); reloaded.LockedUntil != nil || reloaded.FailedLoginAttempts != 0 {
		t.Errorf("counters not reset after a successful login: %+v", reloaded)
	}
}

func TestLockoutRevokesLiveSessions(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)
	session := f.login("alice", testPassword)

	for i := 0; i < 3; i++ {
		_, _ = f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
			Username: "alice",
			Password: "wrong-password-1",
		})
	}

	_, _, err := f.service.ResolveSession(context.Background(), session.Token)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired once the account got locked", err)
	}
}

func TestLoginWithTwoFactorRequiresCode(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)
	f.enableTOTP(user.ID)

	pending, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "alice",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("password step: %v", err)
	}
	if pending.Status != auth.StatusTOTPRequired {
		t.Fatalf("status = %q, want totp_required", pending.Status)
	}
	if pending.Token != "" {
		t.Fatal("no session may be issued before the code is verified")
	}

	if _, err := f.service.CompleteTOTPChallenge(context.Background(), pending.ChallengeID, "000000", "unit-test"); err == nil {
		t.Fatal("expected a wrong code to be refused")
	} else {
		var codeErr *auth.TOTPError
		if !errors.As(err, &codeErr) {
			t.Fatalf("err = %v, want a TOTPError", err)
		}
		if codeErr.RemainingAttempts != 2 {
			t.Errorf("remaining = %d, want 2 (wrong codes count towards the lockout)", codeErr.RemainingAttempts)
		}
	}

	result, err := f.service.CompleteTOTPChallenge(context.Background(), pending.ChallengeID, validCode, "unit-test")
	if err != nil {
		t.Fatalf("code step: %v", err)
	}
	if result.Status != auth.StatusAuthenticated || result.Token == "" {
		t.Fatalf("result = %+v, want an authenticated session", result)
	}
}

func TestTwoFactorChallengeExpires(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)
	f.enableTOTP(user.ID)

	pending, err := f.service.Authenticate(context.Background(), auth.AuthenticateRequest{
		Username: "alice",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("password step: %v", err)
	}

	f.clock.Advance(3 * time.Minute)

	_, err = f.service.CompleteTOTPChallenge(context.Background(), pending.ChallengeID, validCode, "unit-test")
	if !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("err = %v, want ErrChallengeExpired", err)
	}
}

func TestEnableTwoFactorStoresEncryptedSecret(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)

	enrollment, err := f.service.BeginTOTPEnrollment(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if enrollment.Secret != totpSecret || !strings.HasPrefix(enrollment.URI, "otpauth://") {
		t.Fatalf("enrollment = %+v, want a secret and an otpauth URI", enrollment)
	}

	pending := f.reload(user.ID)
	if pending.TOTPEnabled {
		t.Error("two factor must stay off until the code is confirmed")
	}
	if !pending.HasPendingTOTPEnrollment() {
		t.Error("expected a pending enrollment")
	}
	if strings.Contains(pending.TOTPSecret, totpSecret) {
		t.Error("the shared secret must not be stored in the clear")
	}

	if err := f.service.ConfirmTOTPEnrollment(context.Background(), user.ID, "999999", 0); !errors.Is(err, auth.ErrInvalidTOTPCode) {
		t.Fatalf("err = %v, want ErrInvalidTOTPCode", err)
	}
	if f.reload(user.ID).TOTPEnabled {
		t.Fatal("a wrong code must not enable two factor")
	}

	if err := f.service.ConfirmTOTPEnrollment(context.Background(), user.ID, validCode, 0); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	enabled := f.reload(user.ID)
	if !enabled.TOTPEnabled || enabled.TOTPConfirmedAt == nil {
		t.Fatalf("user = %+v, want two factor enabled with a confirmation time", enabled)
	}
	if !f.hasEvent(domain.EventTOTPEnabled) {
		t.Error("expected a totp_enabled audit event")
	}
}

func TestDisableTwoFactorNeedsAValidCode(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)
	f.enableTOTP(user.ID)

	if err := f.service.DisableTOTP(context.Background(), user.ID, "000000", 0); !errors.Is(err, auth.ErrInvalidTOTPCode) {
		t.Fatalf("err = %v, want ErrInvalidTOTPCode", err)
	}
	if !f.reload(user.ID).TOTPEnabled {
		t.Fatal("two factor must stay enabled after a wrong code")
	}

	if err := f.service.DisableTOTP(context.Background(), user.ID, validCode, 0); err != nil {
		t.Fatalf("disable: %v", err)
	}
	disabled := f.reload(user.ID)
	if disabled.TOTPEnabled || disabled.TOTPSecret != "" {
		t.Fatalf("user = %+v, want two factor off and the secret cleared", disabled)
	}

	if err := f.service.DisableTOTP(context.Background(), user.ID, validCode, 0); !errors.Is(err, auth.ErrTOTPNotEnabled) {
		t.Fatalf("err = %v, want ErrTOTPNotEnabled", err)
	}
}

func TestEnableTwoFactorRevokesOtherSessions(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)
	first := f.login("alice", testPassword)
	second := f.login("alice", testPassword)

	if _, err := f.service.BeginTOTPEnrollment(context.Background(), user.ID); err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if err := f.service.ConfirmTOTPEnrollment(context.Background(), user.ID, validCode, first.Session.ID); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}

	if _, _, err := f.service.ResolveSession(context.Background(), first.Token); err != nil {
		t.Fatalf("the session that enabled 2FA should stay alive: %v", err)
	}
	if _, _, err := f.service.ResolveSession(context.Background(), second.Token); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want the other session revoked", err)
	}
}

func TestCancelPendingEnrollmentDropsTheSecret(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)

	if _, err := f.service.BeginTOTPEnrollment(context.Background(), user.ID); err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if err := f.service.CancelTOTPEnrollment(context.Background(), user.ID); err != nil {
		t.Fatalf("cancel enrollment: %v", err)
	}
	if f.reload(user.ID).TOTPSecret != "" {
		t.Error("expected the pending secret to be removed")
	}
}

func TestSessionSlidesForwardUntilTheAbsoluteLimit(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)
	login := f.login("alice", testPassword)

	// Activity every 10 minutes keeps the 15 minute idle window open.
	for i := 0; i < 5; i++ {
		f.clock.Advance(10 * time.Minute)
		if _, _, err := f.service.ResolveSession(context.Background(), login.Token); err != nil {
			t.Fatalf("resolve after %d minutes: %v", (i+1)*10, err)
		}
	}

	// The absolute lifetime is one hour, so the next hop is refused even though
	// the account has been active all along.
	f.clock.Advance(11 * time.Minute)
	if _, _, err := f.service.ResolveSession(context.Background(), login.Token); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired at the absolute limit", err)
	}
}

func TestSessionExpiresWhenIdle(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)
	login := f.login("alice", testPassword)

	f.clock.Advance(16 * time.Minute)

	_, _, err := f.service.ResolveSession(context.Background(), login.Token)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
	if !f.hasEvent(domain.EventSessionExpired) {
		t.Error("expected a session_expired audit event")
	}
}

func TestLogoutInvalidatesTheToken(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)
	login := f.login("alice", testPassword)

	if err := f.service.Logout(context.Background(), login.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := f.service.ResolveSession(context.Background(), login.Token); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired after logout", err)
	}
	if !f.hasEvent(domain.EventLogout) {
		t.Error("expected a logout audit event")
	}

	// Logging out twice is harmless.
	if err := f.service.Logout(context.Background(), login.Token); err != nil {
		t.Fatalf("second logout: %v", err)
	}
}

func TestResolveSessionRejectsAForgedToken(t *testing.T) {
	f := newFixture(t)
	f.register("alice", testPassword)
	f.login("alice", testPassword)

	if _, _, err := f.service.ResolveSession(context.Background(), "not-a-real-token"); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

func TestRecentActivityReturnsNewestFirst(t *testing.T) {
	f := newFixture(t)
	user := f.register("alice", testPassword)
	f.clock.Advance(time.Minute)
	f.login("alice", testPassword)

	events, err := f.service.RecentActivity(context.Background(), user.ID, 5)
	if err != nil {
		t.Fatalf("recent activity: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("got %d events, want at least 2", len(events))
	}
	if events[0].Type != domain.EventLoginSucceeded {
		t.Errorf("newest event = %q, want login_succeeded", events[0].Type)
	}
}

// enableTOTP takes an account through the full enrollment so the tests that
// only care about login do not have to repeat it.
func (f *fixture) enableTOTP(userID int64) {
	f.t.Helper()
	if _, err := f.service.BeginTOTPEnrollment(context.Background(), userID); err != nil {
		f.t.Fatalf("begin enrollment: %v", err)
	}
	if err := f.service.ConfirmTOTPEnrollment(context.Background(), userID, validCode, 0); err != nil {
		f.t.Fatalf("confirm enrollment: %v", err)
	}
}
