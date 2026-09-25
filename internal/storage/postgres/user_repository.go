package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// UserRepository is the Postgres implementation of domain.UserRepository.
type UserRepository struct {
	repository
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{repository{db: db}}
}

const userColumns = `id, username, password_hash, totp_secret, totp_enabled, totp_confirmed_at,
	failed_login_attempts, locked_until, last_login_at, created_at, updated_at`

func (r *UserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	const query = `
		INSERT INTO users (username, password_hash, totp_secret, totp_enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + userColumns

	row := r.exec(ctx).QueryRowContext(ctx, query,
		user.Username,
		user.PasswordHash,
		user.TOTPSecret,
		user.TOTPEnabled,
		user.CreatedAt,
		user.UpdatedAt,
	)

	created, err := scanUser(row)
	if err != nil {
		if isUniqueViolation(err, "users_username_key") {
			return nil, domain.ErrUsernameTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return created, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1`

	user, err := scanUser(r.exec(ctx).QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("select user by id: %w", err)
	}
	return user, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE username = $1`

	user, err := scanUser(r.exec(ctx).QueryRowContext(ctx, query, username))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("select user by username: %w", err)
	}
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	const query = `
		UPDATE users
		   SET password_hash         = $2,
		       totp_secret           = $3,
		       totp_enabled          = $4,
		       totp_confirmed_at     = $5,
		       failed_login_attempts = $6,
		       locked_until          = $7,
		       last_login_at         = $8,
		       updated_at            = $9
		 WHERE id = $1`

	// The service stamps UpdatedAt from its clock; the fallback only covers
	// callers that forgot to.
	updatedAt := user.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	result, err := r.exec(ctx).ExecContext(ctx, query,
		user.ID,
		user.PasswordHash,
		user.TOTPSecret,
		user.TOTPEnabled,
		user.TOTPConfirmedAt,
		user.FailedLoginAttempts,
		user.LockedUntil,
		user.LastLoginAt,
		updatedAt,
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if affected == 0 {
		return domain.ErrNotFound
	}
	user.UpdatedAt = updatedAt
	return nil
}

// rowScanner covers both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*domain.User, error) {
	var (
		user            domain.User
		totpConfirmedAt sql.NullTime
		lockedUntil     sql.NullTime
		lastLoginAt     sql.NullTime
	)

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&totpConfirmedAt,
		&user.FailedLoginAttempts,
		&lockedUntil,
		&lastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, err
	}

	user.TOTPConfirmedAt = nullTimeToPtr(totpConfirmedAt)
	user.LockedUntil = nullTimeToPtr(lockedUntil)
	user.LastLoginAt = nullTimeToPtr(lastLoginAt)
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()

	return &user, nil
}

// nullTimeToPtr keeps the UTC normalisation in one place: the CLI formats these
// values for display and mixed zones would be confusing.
func nullTimeToPtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}
