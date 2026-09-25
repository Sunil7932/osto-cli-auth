package domain

import (
	"context"
	"time"
)

// The interfaces below are the ports of the application core. The auth service
// depends only on these, which is what lets the same service run against
// Postgres in production and against an in-memory store in the unit tests.

type UserRepository interface {
	Create(ctx context.Context, user *User) (*User, error)
	FindByID(ctx context.Context, id int64) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	// Update persists the mutable columns of an existing user.
	Update(ctx context.Context, user *User) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *Session) (*Session, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	// Touch extends the idle deadline of an active session.
	Touch(ctx context.Context, id int64, lastSeenAt, idleExpiresAt time.Time) error
	Revoke(ctx context.Context, id int64, revokedAt time.Time) error
	RevokeAllForUser(ctx context.Context, userID int64, revokedAt time.Time) (int64, error)
	// RevokeAllForUserExcept is used when the security posture of an account
	// changes (2FA on/off) but the session that just proved the change should
	// stay alive.
	RevokeAllForUserExcept(ctx context.Context, userID, exceptID int64, revokedAt time.Time) (int64, error)
	// DeleteExpired prunes sessions that can no longer be used.
	DeleteExpired(ctx context.Context, olderThan time.Time) (int64, error)
}

type EventRepository interface {
	Append(ctx context.Context, event AuthEvent) error
	RecentForUser(ctx context.Context, userID int64, limit int) ([]AuthEvent, error)
}

// TxManager runs a unit of work atomically. Implementations put the
// transaction on the context so repositories transparently join it.
type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}
