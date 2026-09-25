// Package auth contains the application core: registration, login, two factor
// enrollment, lockout and session handling.
//
// The service only talks to the ports declared in internal/domain, so it has
// no knowledge of Postgres or of the CLI that drives it.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// Status is the outcome of a password check.
type Status string

const (
	// StatusAuthenticated means a session was issued.
	StatusAuthenticated Status = "authenticated"
	// StatusTOTPRequired means the password was correct but the account has
	// two factor enabled, so a code is still needed.
	StatusTOTPRequired Status = "totp_required"
)

// AuthenticateRequest is the first step of a login.
type AuthenticateRequest struct {
	Username string
	Password string
	// ClientInfo is stored with the session for auditing, e.g. "host/pid".
	ClientInfo string
}

// Result describes where a login ended up.
type Result struct {
	Status      Status
	User        *domain.User
	Session     *domain.Session
	Token       string
	ChallengeID string
	// PreviousLoginAt is the login before this one, which is what a user
	// actually wants to see after signing in.
	PreviousLoginAt *time.Time
}

// Dependencies are the collaborators the service cannot work without.
type Dependencies struct {
	Users      domain.UserRepository
	Sessions   domain.SessionRepository
	Events     domain.EventRepository
	Tx         domain.TxManager
	Hasher     PasswordHasher
	TOTP       TOTPProvider
	Cipher     SecretCipher
	Challenges ChallengeStore
	Clock      clock.Clock
}

// Option tunes the service. Everything optional is set this way so adding a
// knob later does not break existing callers.
type Option func(*Service)

func WithPasswordPolicy(policy PasswordPolicy) Option {
	return func(s *Service) { s.policy = policy }
}

func WithLockoutPolicy(policy LockoutPolicy) Option {
	return func(s *Service) { s.lockout = policy }
}

func WithSessionWindow(idleTimeout, maxLifetime time.Duration) Option {
	return func(s *Service) {
		s.idleTimeout = idleTimeout
		s.maxLifetime = maxLifetime
	}
}

func WithChallengeTTL(ttl time.Duration) Option {
	return func(s *Service) { s.challengeTTL = ttl }
}

// Service is the façade the CLI talks to.
type Service struct {
	users      domain.UserRepository
	events     domain.EventRepository
	tx         domain.TxManager
	hasher     PasswordHasher
	totp       TOTPProvider
	cipher     SecretCipher
	challenges ChallengeStore
	clock      clock.Clock

	sessions *SessionManager

	policy       PasswordPolicy
	lockout      LockoutPolicy
	idleTimeout  time.Duration
	maxLifetime  time.Duration
	challengeTTL time.Duration

	// decoyHash is compared against when the username does not exist, so that
	// both branches of a login take roughly the same time.
	decoyOnce sync.Once
	decoyHash string
}

func NewService(deps Dependencies, opts ...Option) (*Service, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}

	svc := &Service{
		users:        deps.Users,
		events:       deps.Events,
		tx:           deps.Tx,
		hasher:       deps.Hasher,
		totp:         deps.TOTP,
		cipher:       deps.Cipher,
		challenges:   deps.Challenges,
		clock:        deps.Clock,
		policy:       DefaultPasswordPolicy(),
		lockout:      DefaultLockoutPolicy(),
		idleTimeout:  15 * time.Minute,
		maxLifetime:  8 * time.Hour,
		challengeTTL: 2 * time.Minute,
	}
	for _, opt := range opts {
		opt(svc)
	}

	svc.sessions = NewSessionManager(deps.Sessions, deps.Clock, svc.idleTimeout, svc.maxLifetime)
	svc.primeDecoy()
	return svc, nil
}

func (d Dependencies) validate() error {
	missing := make([]string, 0, 8)
	if d.Users == nil {
		missing = append(missing, "Users")
	}
	if d.Sessions == nil {
		missing = append(missing, "Sessions")
	}
	if d.Events == nil {
		missing = append(missing, "Events")
	}
	if d.Tx == nil {
		missing = append(missing, "Tx")
	}
	if d.Hasher == nil {
		missing = append(missing, "Hasher")
	}
	if d.TOTP == nil {
		missing = append(missing, "TOTP")
	}
	if d.Cipher == nil {
		missing = append(missing, "Cipher")
	}
	if d.Challenges == nil {
		missing = append(missing, "Challenges")
	}
	if d.Clock == nil {
		missing = append(missing, "Clock")
	}
	if len(missing) > 0 {
		return fmt.Errorf("auth service is missing dependencies: %v", missing)
	}
	return nil
}

// SessionWindow exposes the configured timeouts, used by the CLI when it
// explains session behaviour to the user.
func (s *Service) SessionWindow() (idleTimeout, maxLifetime time.Duration) {
	return s.idleTimeout, s.maxLifetime
}

// PasswordPolicy is exposed so the register prompt can state the rules up
// front instead of only failing afterwards.
func (s *Service) PasswordPolicy() PasswordPolicy { return s.policy }

// Register creates an account. Username comparison is case insensitive.
func (s *Service) Register(ctx context.Context, username, password string) (*domain.User, error) {
	name := domain.NormalizeUsername(username)
	if err := domain.ValidateUsername(name); err != nil {
		return nil, err
	}
	if err := s.policy.Validate(name, password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()
	var created *domain.User
	err = s.tx.WithinTx(ctx, func(ctx context.Context) error {
		user, err := s.users.Create(ctx, &domain.User{
			Username:     name,
			PasswordHash: hash,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return err
		}
		created = user
		return s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  name,
			Type:      domain.EventRegistered,
			CreatedAt: now,
		})
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// Authenticate verifies the password. When the account has two factor enabled
// the result carries a challenge id instead of a session, and the caller has to
// follow up with CompleteTOTPChallenge.
func (s *Service) Authenticate(ctx context.Context, req AuthenticateRequest) (*Result, error) {
	name := domain.NormalizeUsername(req.Username)
	now := s.clock.Now()

	user, err := s.users.FindByUsername(ctx, name)
	if err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, fmt.Errorf("load user: %w", err)
		}
		// Burn the same work a real password check would, otherwise response
		// time alone reveals which usernames exist.
		_ = s.hasher.Verify(s.decoy(), req.Password)
		s.recordEvent(ctx, domain.AuthEvent{
			Username:  name,
			Type:      domain.EventLoginFailed,
			Detail:    "unknown username",
			CreatedAt: now,
		})
		return nil, &CredentialError{RemainingAttempts: -1}
	}

	if user.IsLocked(now) {
		s.recordEvent(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  name,
			Type:      domain.EventLoginFailed,
			Detail:    "attempt while locked out",
			CreatedAt: now,
		})
		return nil, &AccountLockedError{Until: *user.LockedUntil}
	}
	if s.lockout.ClearExpiredLock(user, now) {
		if err := s.persistUser(ctx, user); err != nil {
			return nil, err
		}
	}

	if err := s.hasher.Verify(user.PasswordHash, req.Password); err != nil {
		if !errors.Is(err, ErrPasswordMismatch) {
			return nil, err
		}
		outcome, ferr := s.recordFailure(ctx, user, domain.EventLoginFailed, "wrong password")
		if ferr != nil {
			return nil, ferr
		}
		if outcome.Locked {
			return nil, &AccountLockedError{Until: outcome.LockedUntil}
		}
		return nil, &CredentialError{RemainingAttempts: outcome.Remaining}
	}

	// Cost was raised since the account was created: take the free upgrade while
	// the plaintext is in hand. Persisted right away because a two factor login
	// reloads the user before it finishes.
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if hash, err := s.hasher.Hash(req.Password); err == nil {
			user.PasswordHash = hash
			if err := s.persistUser(ctx, user); err != nil {
				return nil, err
			}
		}
	}

	if user.TOTPEnabled {
		id, err := newChallengeID()
		if err != nil {
			return nil, err
		}
		challenge := Challenge{
			ID:        id,
			UserID:    user.ID,
			Username:  user.Username,
			ExpiresAt: now.Add(s.challengeTTL),
		}
		if err := s.challenges.Save(ctx, challenge); err != nil {
			return nil, fmt.Errorf("store two factor challenge: %w", err)
		}
		s.recordEvent(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventTOTPChallenged,
			CreatedAt: now,
		})
		return &Result{Status: StatusTOTPRequired, User: user, ChallengeID: id}, nil
	}

	return s.completeLogin(ctx, user, req.ClientInfo)
}

// CompleteTOTPChallenge finishes a login that was parked waiting for a code.
func (s *Service) CompleteTOTPChallenge(ctx context.Context, challengeID, code, clientInfo string) (*Result, error) {
	challenge, err := s.challenges.Find(ctx, challengeID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrChallengeExpired
		}
		return nil, fmt.Errorf("load two factor challenge: %w", err)
	}

	user, err := s.users.FindByID(ctx, challenge.UserID)
	if err != nil {
		_ = s.challenges.Delete(ctx, challengeID)
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrChallengeExpired
		}
		return nil, fmt.Errorf("load user: %w", err)
	}

	now := s.clock.Now()
	if user.IsLocked(now) {
		_ = s.challenges.Delete(ctx, challengeID)
		return nil, &AccountLockedError{Until: *user.LockedUntil}
	}
	if !user.TOTPEnabled {
		// 2FA was turned off from another session while this one waited.
		_ = s.challenges.Delete(ctx, challengeID)
		return nil, ErrChallengeExpired
	}

	secret, err := s.cipher.Decrypt(user.TOTPSecret)
	if err != nil {
		return nil, fmt.Errorf("read two factor secret: %w", err)
	}

	if !s.totp.Verify(secret, code, now) {
		challenge.Attempts++
		if err := s.challenges.Save(ctx, challenge); err != nil {
			return nil, fmt.Errorf("store two factor challenge: %w", err)
		}
		outcome, ferr := s.recordFailure(ctx, user, domain.EventTOTPFailed,
			fmt.Sprintf("invalid code, attempt %d", challenge.Attempts))
		if ferr != nil {
			return nil, ferr
		}
		if outcome.Locked {
			_ = s.challenges.Delete(ctx, challengeID)
			return nil, &AccountLockedError{Until: outcome.LockedUntil}
		}
		return nil, &TOTPError{RemainingAttempts: outcome.Remaining}
	}

	if err := s.challenges.Delete(ctx, challengeID); err != nil {
		return nil, fmt.Errorf("clear two factor challenge: %w", err)
	}
	return s.completeLogin(ctx, user, clientInfo)
}

// AbandonChallenge drops a pending challenge, for example when the user hits
// Ctrl-C at the code prompt.
func (s *Service) AbandonChallenge(ctx context.Context, challengeID string) {
	if challengeID == "" {
		return
	}
	_ = s.challenges.Delete(ctx, challengeID)
}

// ResolveSession validates a token and returns the session together with its
// owner. Every authenticated command goes through here, which is what makes
// the idle timeout effective.
func (s *Service) ResolveSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	session, err := s.sessions.Resolve(ctx, token)
	if err != nil {
		if errors.Is(err, ErrSessionExpired) && session != nil {
			s.recordEvent(ctx, domain.AuthEvent{
				UserID:    &session.UserID,
				Type:      domain.EventSessionExpired,
				CreatedAt: s.clock.Now(),
			})
		}
		return nil, nil, err
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, ErrSessionExpired
		}
		return nil, nil, fmt.Errorf("load user: %w", err)
	}
	return session, user, nil
}

// Logout revokes the session behind token.
func (s *Service) Logout(ctx context.Context, token string) error {
	session, err := s.sessions.Revoke(ctx, token)
	if err != nil {
		return err
	}
	if session != nil {
		s.recordEvent(ctx, domain.AuthEvent{
			UserID:    &session.UserID,
			Type:      domain.EventLogout,
			CreatedAt: s.clock.Now(),
		})
	}
	return nil
}

// BeginTOTPEnrollment creates (or replaces) a pending enrollment and returns
// the provisioning data for the authenticator app. Two factor is not active
// until ConfirmTOTPEnrollment succeeds.
func (s *Service) BeginTOTPEnrollment(ctx context.Context, userID int64) (Enrollment, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("load user: %w", err)
	}
	if user.TOTPEnabled {
		return Enrollment{}, ErrTOTPAlreadyEnabled
	}

	enrollment, err := s.totp.Enroll(user.Username)
	if err != nil {
		return Enrollment{}, err
	}
	encrypted, err := s.cipher.Encrypt(enrollment.Secret)
	if err != nil {
		return Enrollment{}, fmt.Errorf("protect two factor secret: %w", err)
	}

	user.TOTPSecret = encrypted
	user.TOTPEnabled = false
	user.TOTPConfirmedAt = nil
	if err := s.persistUser(ctx, user); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

// ConfirmTOTPEnrollment turns 2FA on after the user proves they can read codes
// from the secret. Other sessions are revoked so they have to log in again
// with the new factor. keepSessionID is left alone; pass 0 to revoke all.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, userID int64, code string, keepSessionID int64) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}
	if user.TOTPEnabled {
		return ErrTOTPAlreadyEnabled
	}
	if !user.HasPendingTOTPEnrollment() {
		return ErrNoPendingEnrollment
	}

	secret, err := s.cipher.Decrypt(user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("read two factor secret: %w", err)
	}

	now := s.clock.Now()
	if !s.totp.Verify(secret, code, now) {
		s.recordEvent(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventTOTPFailed,
			Detail:    "enrollment confirmation failed",
			CreatedAt: now,
		})
		return ErrInvalidTOTPCode
	}

	user.TOTPEnabled = true
	user.TOTPConfirmedAt = &now
	user.UpdatedAt = now
	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.users.Update(ctx, user); err != nil {
			return err
		}
		if _, err := s.sessions.RevokeOthers(ctx, user.ID, keepSessionID); err != nil {
			return err
		}
		return s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventTOTPEnabled,
			CreatedAt: now,
		})
	})
}

// CancelTOTPEnrollment throws away a pending enrollment.
func (s *Service) CancelTOTPEnrollment(ctx context.Context, userID int64) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}
	if !user.HasPendingTOTPEnrollment() {
		return nil
	}
	user.TOTPSecret = ""
	return s.persistUser(ctx, user)
}

// DisableTOTP turns two factor off. A valid code is required, otherwise
// someone who walks up to an unlocked terminal could strip the second factor.
func (s *Service) DisableTOTP(ctx context.Context, userID int64, code string, keepSessionID int64) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	secret, err := s.cipher.Decrypt(user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("read two factor secret: %w", err)
	}

	now := s.clock.Now()
	if !s.totp.Verify(secret, code, now) {
		s.recordEvent(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventTOTPFailed,
			Detail:    "disable request failed",
			CreatedAt: now,
		})
		return ErrInvalidTOTPCode
	}

	user.TOTPEnabled = false
	user.TOTPSecret = ""
	user.TOTPConfirmedAt = nil
	user.UpdatedAt = now
	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.users.Update(ctx, user); err != nil {
			return err
		}
		if _, err := s.sessions.RevokeOthers(ctx, user.ID, keepSessionID); err != nil {
			return err
		}
		return s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventTOTPDisabled,
			CreatedAt: now,
		})
	})
}

// RecentActivity returns the latest audit entries for an account.
func (s *Service) RecentActivity(ctx context.Context, userID int64, limit int) ([]domain.AuthEvent, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.events.RecentForUser(ctx, userID, limit)
}

// PurgeExpiredSessions is housekeeping, called once on startup.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	return s.sessions.PurgeExpired(ctx)
}

// failureOutcome is the result of counting one failed attempt.
type failureOutcome struct {
	Locked      bool
	LockedUntil time.Time
	Remaining   int
}

// recordFailure persists a failed attempt, locking the account when the policy
// says so, and revoking any live session of that account along with it.
func (s *Service) recordFailure(ctx context.Context, user *domain.User, eventType domain.EventType, detail string) (failureOutcome, error) {
	now := s.clock.Now()
	locked := s.lockout.RegisterFailure(user, now)
	user.UpdatedAt = now

	err := s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.users.Update(ctx, user); err != nil {
			return err
		}
		if err := s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      eventType,
			Detail:    detail,
			CreatedAt: now,
		}); err != nil {
			return err
		}
		if !locked {
			return nil
		}
		if _, err := s.sessions.RevokeAllForUser(ctx, user.ID); err != nil {
			return err
		}
		return s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventAccountLocked,
			Detail:    fmt.Sprintf("locked until %s", user.LockedUntil.Format(time.RFC3339)),
			CreatedAt: now,
		})
	})
	if err != nil {
		return failureOutcome{}, err
	}

	outcome := failureOutcome{Locked: locked, Remaining: s.lockout.RemainingAttempts(user)}
	if locked {
		outcome.LockedUntil = *user.LockedUntil
		outcome.Remaining = 0
	}
	return outcome, nil
}

func (s *Service) completeLogin(ctx context.Context, user *domain.User, clientInfo string) (*Result, error) {
	now := s.clock.Now()
	previousLogin := user.LastLoginAt

	s.lockout.Reset(user)
	user.LastLoginAt = &now
	user.UpdatedAt = now

	var (
		session *domain.Session
		token   string
	)
	err := s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.users.Update(ctx, user); err != nil {
			return err
		}
		issued, tok, err := s.sessions.Issue(ctx, user.ID, clientInfo)
		if err != nil {
			return err
		}
		session, token = issued, tok
		return s.events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      domain.EventLoginSucceeded,
			Detail:    clientInfo,
			CreatedAt: now,
		})
	})
	if err != nil {
		return nil, err
	}

	return &Result{
		Status:          StatusAuthenticated,
		User:            user,
		Session:         session,
		Token:           token,
		PreviousLoginAt: previousLogin,
	}, nil
}

func (s *Service) persistUser(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = s.clock.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// recordEvent writes an audit entry outside of any transaction. Audit writes
// must never turn a successful operation into a failure, so errors are
// swallowed on purpose.
func (s *Service) recordEvent(ctx context.Context, event domain.AuthEvent) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = s.clock.Now()
	}
	_ = s.events.Append(ctx, event)
}

func (s *Service) primeDecoy() {
	buf := make([]byte, 24)
	plain := "decoy-password-for-timing"
	if _, err := rand.Read(buf); err == nil {
		plain = base64.RawStdEncoding.EncodeToString(buf)
	}
	hash, err := s.hasher.Hash(plain)
	if err != nil {
		return
	}
	s.decoyHash = hash
}

func (s *Service) decoy() string {
	if s.decoyHash != "" {
		return s.decoyHash
	}
	// NewService already tried; this is only if hashing failed at startup.
	s.decoyOnce.Do(s.primeDecoy)
	return s.decoyHash
}
