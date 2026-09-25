package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// tokenBytes is the entropy of a session token before encoding.
const tokenBytes = 32

// SessionManager owns the lifecycle of sessions: issuing tokens, refreshing
// the idle deadline and revoking on logout.
type SessionManager struct {
	repo        domain.SessionRepository
	clock       clock.Clock
	idleTimeout time.Duration
	maxLifetime time.Duration
}

func NewSessionManager(repo domain.SessionRepository, clk clock.Clock, idleTimeout, maxLifetime time.Duration) *SessionManager {
	return &SessionManager{
		repo:        repo,
		clock:       clk,
		idleTimeout: idleTimeout,
		maxLifetime: maxLifetime,
	}
}

// Issue creates a session for the user and returns it together with the
// plaintext token. The token is the only copy: the database keeps a hash.
func (m *SessionManager) Issue(ctx context.Context, userID int64, clientInfo string) (*domain.Session, string, error) {
	token, err := newSessionToken()
	if err != nil {
		return nil, "", err
	}

	now := m.clock.Now()
	session := &domain.Session{
		UserID:            userID,
		TokenHash:         HashToken(token),
		IssuedAt:          now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(m.idleTimeout),
		AbsoluteExpiresAt: now.Add(m.maxLifetime),
		ClientInfo:        clientInfo,
	}

	stored, err := m.repo.Create(ctx, session)
	if err != nil {
		return nil, "", fmt.Errorf("persist session: %w", err)
	}
	return stored, token, nil
}

// Resolve validates a token and slides the idle deadline forward. An unknown,
// revoked or expired token all produce ErrSessionExpired so a stale token
// cannot be told apart from a forged one.
func (m *SessionManager) Resolve(ctx context.Context, token string) (*domain.Session, error) {
	session, err := m.repo.FindByTokenHash(ctx, HashToken(token))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrSessionExpired
		}
		return nil, fmt.Errorf("load session: %w", err)
	}

	now := m.clock.Now()
	if !session.IsActive(now) {
		return session, ErrSessionExpired
	}

	idleExpiry := now.Add(m.idleTimeout)
	if idleExpiry.After(session.AbsoluteExpiresAt) {
		idleExpiry = session.AbsoluteExpiresAt
	}
	if err := m.repo.Touch(ctx, session.ID, now, idleExpiry); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// Revoked between the lookup and the update, for example by a
			// lockout triggered from another shell.
			return session, ErrSessionExpired
		}
		return nil, fmt.Errorf("refresh session: %w", err)
	}
	session.LastSeenAt = now
	session.IdleExpiresAt = idleExpiry

	return session, nil
}

// Revoke ends a session and returns it, or nil when the token was unknown.
// Revoking an already dead session is not an error.
func (m *SessionManager) Revoke(ctx context.Context, token string) (*domain.Session, error) {
	session, err := m.repo.FindByTokenHash(ctx, HashToken(token))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load session: %w", err)
	}
	if session.RevokedAt != nil {
		return session, nil
	}

	now := m.clock.Now()
	if err := m.repo.Revoke(ctx, session.ID, now); err != nil {
		return nil, fmt.Errorf("revoke session: %w", err)
	}
	session.RevokedAt = &now
	return session, nil
}

// RevokeAllForUser kills every live session of the account. Used on lockout.
func (m *SessionManager) RevokeAllForUser(ctx context.Context, userID int64) (int64, error) {
	return m.repo.RevokeAllForUser(ctx, userID, m.clock.Now())
}

// RevokeOthers leaves keepID alone and kills the rest. keepID 0 means all of
// them, which is what the unit tests use when there is no current session.
func (m *SessionManager) RevokeOthers(ctx context.Context, userID, keepID int64) (int64, error) {
	now := m.clock.Now()
	if keepID == 0 {
		return m.repo.RevokeAllForUser(ctx, userID, now)
	}
	return m.repo.RevokeAllForUserExcept(ctx, userID, keepID, now)
}

// PurgeExpired removes sessions that can no longer be resolved. It runs once
// at startup to keep the table from growing forever.
func (m *SessionManager) PurgeExpired(ctx context.Context) (int64, error) {
	return m.repo.DeleteExpired(ctx, m.clock.Now())
}

// HashToken is the one way function applied before a token touches storage.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newSessionToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
