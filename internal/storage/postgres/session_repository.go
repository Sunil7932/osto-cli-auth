package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// SessionRepository is the Postgres implementation of domain.SessionRepository.
type SessionRepository struct {
	repository
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{repository{db: db}}
}

const sessionColumns = `id, user_id, token_hash, issued_at, last_seen_at, idle_expires_at,
	absolute_expires_at, revoked_at, client_info`

func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	const query = `
		INSERT INTO sessions (user_id, token_hash, issued_at, last_seen_at, idle_expires_at,
		                      absolute_expires_at, client_info)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + sessionColumns

	created, err := scanSession(r.exec(ctx).QueryRowContext(ctx, query,
		session.UserID,
		session.TokenHash,
		session.IssuedAt,
		session.LastSeenAt,
		session.IdleExpiresAt,
		session.AbsoluteExpiresAt,
		session.ClientInfo,
	))
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return created, nil
}

func (r *SessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	const query = `SELECT ` + sessionColumns + ` FROM sessions WHERE token_hash = $1`

	session, err := scanSession(r.exec(ctx).QueryRowContext(ctx, query, tokenHash))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("select session: %w", err)
	}
	return session, nil
}

func (r *SessionRepository) Touch(ctx context.Context, id int64, lastSeenAt, idleExpiresAt time.Time) error {
	const query = `
		UPDATE sessions
		   SET last_seen_at    = $2,
		       idle_expires_at = $3
		 WHERE id = $1
		   AND revoked_at IS NULL`

	result, err := r.exec(ctx).ExecContext(ctx, query, id, lastSeenAt, idleExpiresAt)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	if affected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id int64, revokedAt time.Time) error {
	const query = `
		UPDATE sessions
		   SET revoked_at = $2
		 WHERE id = $1
		   AND revoked_at IS NULL`

	if _, err := r.exec(ctx).ExecContext(ctx, query, id, revokedAt); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID int64, revokedAt time.Time) (int64, error) {
	return r.revokeMatching(ctx, userID, 0, revokedAt)
}

func (r *SessionRepository) RevokeAllForUserExcept(ctx context.Context, userID, exceptID int64, revokedAt time.Time) (int64, error) {
	return r.revokeMatching(ctx, userID, exceptID, revokedAt)
}

func (r *SessionRepository) revokeMatching(ctx context.Context, userID, exceptID int64, revokedAt time.Time) (int64, error) {
	const query = `
		UPDATE sessions
		   SET revoked_at = $2
		 WHERE user_id = $1
		   AND revoked_at IS NULL
		   AND ($3 = 0 OR id <> $3)`

	result, err := r.exec(ctx).ExecContext(ctx, query, userID, revokedAt, exceptID)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions for user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke sessions for user: %w", err)
	}
	return affected, nil
}

func (r *SessionRepository) DeleteExpired(ctx context.Context, olderThan time.Time) (int64, error) {
	const query = `
		DELETE FROM sessions
		 WHERE revoked_at IS NOT NULL
		    OR idle_expires_at <= $1
		    OR absolute_expires_at <= $1`

	result, err := r.exec(ctx).ExecContext(ctx, query, olderThan)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return affected, nil
}

func scanSession(row rowScanner) (*domain.Session, error) {
	var (
		session   domain.Session
		revokedAt sql.NullTime
	)

	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.IssuedAt,
		&session.LastSeenAt,
		&session.IdleExpiresAt,
		&session.AbsoluteExpiresAt,
		&revokedAt,
		&session.ClientInfo,
	); err != nil {
		return nil, err
	}

	session.RevokedAt = nullTimeToPtr(revokedAt)
	session.IssuedAt = session.IssuedAt.UTC()
	session.LastSeenAt = session.LastSeenAt.UTC()
	session.IdleExpiresAt = session.IdleExpiresAt.UTC()
	session.AbsoluteExpiresAt = session.AbsoluteExpiresAt.UTC()

	return &session, nil
}
