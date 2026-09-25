package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/config"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
	"github.com/Sunil7932/cli-login-2fa/internal/storage/postgres"
)

// These tests talk to a real PostgreSQL instance. They are skipped unless
// TEST_DATABASE_URL is set, for example:
//
//	docker compose up -d db
//	TEST_DATABASE_URL=postgres://authcli:authcli@localhost:55432/authcli?sslmode=disable go test ./...
func testDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set, skipping the database tests")
	}

	db, err := postgres.Open(context.Background(), config.Database{
		DSN:            dsn,
		MaxOpenConns:   4,
		MaxIdleConns:   2,
		ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if _, err := postgres.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	t.Cleanup(func() {
		// Sessions and events reference users, both with ON DELETE rules, so
		// removing the fixtures is enough to leave the database as we found it.
		if _, err := db.Exec(`DELETE FROM users WHERE username LIKE 'itest_%'`); err != nil {
			t.Errorf("clean up fixtures: %v", err)
		}
		db.Close()
	})

	return db
}

func fixtureUsername(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("itest_%d", time.Now().UnixNano())
}

func newUser(t *testing.T, repo domain.UserRepository) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	user, err := repo.Create(context.Background(), &domain.User{
		Username:     fixtureUsername(t),
		PasswordHash: "$2a$04$notarealhashnotarealhashno",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestUserRepositoryCRUD(t *testing.T) {
	db := testDB(t)
	repo := postgres.NewUserRepository(db)
	ctx := context.Background()

	created := newUser(t, repo)
	if created.ID == 0 {
		t.Fatal("expected the database to assign an id")
	}

	byID, err := repo.FindByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if byID.Username != created.Username {
		t.Errorf("username = %q, want %q", byID.Username, created.Username)
	}

	byName, err := repo.FindByUsername(ctx, created.Username)
	if err != nil {
		t.Fatalf("find by username: %v", err)
	}
	if byName.ID != created.ID {
		t.Errorf("id = %d, want %d", byName.ID, created.ID)
	}

	if _, err := repo.FindByUsername(ctx, "itest_does_not_exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := repo.FindByID(ctx, 0); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	duplicate := &domain.User{
		Username:     created.Username,
		PasswordHash: created.PasswordHash,
		CreatedAt:    created.CreatedAt,
		UpdatedAt:    created.UpdatedAt,
	}
	if _, err := repo.Create(ctx, duplicate); !errors.Is(err, domain.ErrUsernameTaken) {
		t.Errorf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestUserRepositoryUpdateRoundTripsNullableColumns(t *testing.T) {
	db := testDB(t)
	repo := postgres.NewUserRepository(db)
	ctx := context.Background()

	user := newUser(t, repo)

	confirmed := time.Now().UTC().Truncate(time.Millisecond)
	lockedUntil := confirmed.Add(10 * time.Minute)
	lastLogin := confirmed.Add(-time.Hour)

	user.TOTPSecret = "encrypted-secret"
	user.TOTPEnabled = true
	user.TOTPConfirmedAt = &confirmed
	user.FailedLoginAttempts = 2
	user.LockedUntil = &lockedUntil
	user.LastLoginAt = &lastLogin

	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("update: %v", err)
	}

	reloaded, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if !reloaded.TOTPEnabled || reloaded.TOTPSecret != "encrypted-secret" {
		t.Errorf("user = %+v, want the two factor fields persisted", reloaded)
	}
	if reloaded.TOTPConfirmedAt == nil || !reloaded.TOTPConfirmedAt.Equal(confirmed) {
		t.Errorf("confirmed at = %v, want %v", reloaded.TOTPConfirmedAt, confirmed)
	}
	if reloaded.LockedUntil == nil || !reloaded.LockedUntil.Equal(lockedUntil) {
		t.Errorf("locked until = %v, want %v", reloaded.LockedUntil, lockedUntil)
	}
	if reloaded.LastLoginAt == nil || !reloaded.LastLoginAt.Equal(lastLogin) {
		t.Errorf("last login = %v, want %v", reloaded.LastLoginAt, lastLogin)
	}
	if reloaded.CreatedAt.Location() != time.UTC {
		t.Errorf("timestamps should come back in UTC, got %v", reloaded.CreatedAt.Location())
	}

	// Clearing the nullable columns has to work as well.
	reloaded.LockedUntil = nil
	reloaded.TOTPConfirmedAt = nil
	if err := repo.Update(ctx, reloaded); err != nil {
		t.Fatalf("second update: %v", err)
	}
	cleared, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if cleared.LockedUntil != nil || cleared.TOTPConfirmedAt != nil {
		t.Errorf("user = %+v, want the nullable columns cleared", cleared)
	}

	missing := &domain.User{ID: -1}
	if err := repo.Update(ctx, missing); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound when updating a row that is gone", err)
	}
}

func TestSessionRepositoryLifecycle(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(db)
	ctx := context.Background()

	user := newUser(t, users)
	now := time.Now().UTC().Truncate(time.Millisecond)

	created, err := sessions.Create(ctx, &domain.Session{
		UserID:            user.ID,
		TokenHash:         fmt.Sprintf("hash-%d", now.UnixNano()),
		IssuedAt:          now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		ClientInfo:        "integration-test",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	found, err := sessions.FindByTokenHash(ctx, created.TokenHash)
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	if !found.IsActive(now) {
		t.Error("a fresh session should be active")
	}

	extended := now.Add(5 * time.Minute)
	if err := sessions.Touch(ctx, created.ID, extended, extended.Add(15*time.Minute)); err != nil {
		t.Fatalf("touch session: %v", err)
	}
	touched, err := sessions.FindByTokenHash(ctx, created.TokenHash)
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	if !touched.IdleExpiresAt.Equal(extended.Add(15 * time.Minute)) {
		t.Errorf("idle expiry = %v, want %v", touched.IdleExpiresAt, extended.Add(15*time.Minute))
	}

	if err := sessions.Revoke(ctx, created.ID, extended); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	revoked, err := sessions.FindByTokenHash(ctx, created.TokenHash)
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	if revoked.RevokedAt == nil || revoked.IsActive(extended) {
		t.Errorf("session = %+v, want it revoked", revoked)
	}

	// Touching a revoked session must not resurrect it.
	if err := sessions.Touch(ctx, created.ID, extended, extended.Add(time.Hour)); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound when touching a revoked session", err)
	}

	if _, err := sessions.FindByTokenHash(ctx, "hash-that-does-not-exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	if _, err := sessions.DeleteExpired(ctx, now.Add(time.Hour)); err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if _, err := sessions.FindByTokenHash(ctx, created.TokenHash); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want the revoked session to have been pruned", err)
	}
}

func TestSessionRepositoryRevokeAllForUser(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(db)
	ctx := context.Background()

	user := newUser(t, users)
	now := time.Now().UTC().Truncate(time.Millisecond)

	for i := 0; i < 3; i++ {
		if _, err := sessions.Create(ctx, &domain.Session{
			UserID:            user.ID,
			TokenHash:         fmt.Sprintf("hash-%d-%d", now.UnixNano(), i),
			IssuedAt:          now,
			LastSeenAt:        now,
			IdleExpiresAt:     now.Add(15 * time.Minute),
			AbsoluteExpiresAt: now.Add(8 * time.Hour),
		}); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}

	revoked, err := sessions.RevokeAllForUser(ctx, user.ID, now)
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if revoked != 3 {
		t.Errorf("revoked %d sessions, want 3", revoked)
	}

	// Running it again finds nothing left to revoke.
	if revoked, err = sessions.RevokeAllForUser(ctx, user.ID, now); err != nil || revoked != 0 {
		t.Errorf("second call = %d, %v, want 0 and nil", revoked, err)
	}
}

func TestSessionRepositoryRevokeAllForUserExcept(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(db)
	ctx := context.Background()

	user := newUser(t, users)
	now := time.Now().UTC().Truncate(time.Millisecond)

	var keep *domain.Session
	for i := 0; i < 3; i++ {
		created, err := sessions.Create(ctx, &domain.Session{
			UserID:            user.ID,
			TokenHash:         fmt.Sprintf("hash-keep-%d-%d", now.UnixNano(), i),
			IssuedAt:          now,
			LastSeenAt:        now,
			IdleExpiresAt:     now.Add(15 * time.Minute),
			AbsoluteExpiresAt: now.Add(8 * time.Hour),
		})
		if err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
		if i == 1 {
			keep = created
		}
	}

	revoked, err := sessions.RevokeAllForUserExcept(ctx, user.ID, keep.ID, now)
	if err != nil {
		t.Fatalf("revoke except: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked %d sessions, want 2", revoked)
	}

	kept, err := sessions.FindByTokenHash(ctx, keep.TokenHash)
	if err != nil {
		t.Fatalf("find kept session: %v", err)
	}
	if kept.RevokedAt != nil {
		t.Error("the excepted session should still be live")
	}
}

func TestEventRepositoryAppendAndRead(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	events := postgres.NewEventRepository(db)
	ctx := context.Background()

	user := newUser(t, users)
	now := time.Now().UTC().Truncate(time.Millisecond)

	for i, eventType := range []domain.EventType{domain.EventRegistered, domain.EventLoginFailed, domain.EventLoginSucceeded} {
		if err := events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  user.Username,
			Type:      eventType,
			Detail:    fmt.Sprintf("event %d", i),
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("append %s: %v", eventType, err)
		}
	}

	// An attempt against a username that does not exist has no user id.
	if err := events.Append(ctx, domain.AuthEvent{
		Username:  "itest_ghost",
		Type:      domain.EventLoginFailed,
		Detail:    "unknown username",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("append anonymous event: %v", err)
	}

	recent, err := events.RecentForUser(ctx, user.ID, 2)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("got %d events, want the 2 most recent", len(recent))
	}
	if recent[0].Type != domain.EventLoginSucceeded {
		t.Errorf("newest event = %q, want login_succeeded", recent[0].Type)
	}
	if recent[0].UserID == nil || *recent[0].UserID != user.ID {
		t.Errorf("event user id = %v, want %d", recent[0].UserID, user.ID)
	}
}

func TestTxManagerRollsBackOnError(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	events := postgres.NewEventRepository(db)
	tx := postgres.NewTxManager(db)
	ctx := context.Background()

	username := fixtureUsername(t)
	sentinel := errors.New("deliberate failure")

	err := tx.WithinTx(ctx, func(ctx context.Context) error {
		now := time.Now().UTC()
		user, err := users.Create(ctx, &domain.User{
			Username:     username,
			PasswordHash: "$2a$04$notarealhashnotarealhashno",
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return err
		}
		if err := events.Append(ctx, domain.AuthEvent{
			UserID:    &user.ID,
			Username:  username,
			Type:      domain.EventRegistered,
			CreatedAt: now,
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel to travel back to the caller", err)
	}

	if _, err := users.FindByUsername(ctx, username); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want the user to have been rolled back", err)
	}
}

func TestTxManagerCommitsAndReusesTheOuterTransaction(t *testing.T) {
	db := testDB(t)
	users := postgres.NewUserRepository(db)
	tx := postgres.NewTxManager(db)
	ctx := context.Background()

	username := fixtureUsername(t)

	err := tx.WithinTx(ctx, func(ctx context.Context) error {
		now := time.Now().UTC()
		user, err := users.Create(ctx, &domain.User{
			Username:     username,
			PasswordHash: "$2a$04$notarealhashnotarealhashno",
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return err
		}
		// A nested unit of work joins the transaction already in flight, so the
		// change it makes is visible to the outer one.
		return tx.WithinTx(ctx, func(ctx context.Context) error {
			user.FailedLoginAttempts = 4
			return users.Update(ctx, user)
		})
	})
	if err != nil {
		t.Fatalf("within tx: %v", err)
	}

	stored, err := users.FindByUsername(ctx, username)
	if err != nil {
		t.Fatalf("find by username: %v", err)
	}
	if stored.FailedLoginAttempts != 4 {
		t.Errorf("failed attempts = %d, want 4 from the nested unit of work", stored.FailedLoginAttempts)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	applied, err := postgres.Migrate(ctx, db)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("second run applied %d migrations, want none", len(applied))
	}

	records, err := postgres.Applied(ctx, db)
	if err != nil {
		t.Fatalf("applied migrations: %v", err)
	}
	available, err := postgres.AvailableMigrations()
	if err != nil {
		t.Fatalf("available migrations: %v", err)
	}
	if len(records) != len(available) {
		t.Errorf("recorded %d migrations, want %d", len(records), len(available))
	}
}
