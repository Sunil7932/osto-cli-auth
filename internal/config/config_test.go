package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadUsesDefaultsWhenTheEnvironmentIsEmpty(t *testing.T) {
	clearEnvironment(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Auth.BcryptCost != 12 {
		t.Errorf("bcrypt cost = %d, want 12", cfg.Auth.BcryptCost)
	}
	if cfg.Auth.SessionIdleTimeout != 15*time.Minute {
		t.Errorf("session timeout = %s, want 15m", cfg.Auth.SessionIdleTimeout)
	}
	if cfg.Auth.MaxPasswordLength != 72 {
		t.Errorf("max password length = %d, want the bcrypt limit of 72", cfg.Auth.MaxPasswordLength)
	}
	if !strings.HasPrefix(cfg.Database.DSN, "postgres://authcli@localhost:5432/authcli") {
		t.Errorf("dsn = %q, want a localhost default", cfg.Database.DSN)
	}
	if !cfg.UsesSampleSecret() {
		t.Error("the default secret key should be flagged as the sample value")
	}
}

func TestLoadReadsTheEnvironment(t *testing.T) {
	clearEnvironment(t)

	t.Setenv("DB_HOST", "db")
	t.Setenv("DB_USER", "app")
	t.Setenv("DB_PASSWORD", "s3cret")
	t.Setenv("DB_NAME", "logins")
	t.Setenv("AUTH_SESSION_TIMEOUT", "45s")
	t.Setenv("AUTH_SESSION_MAX_LIFETIME", "4h")
	t.Setenv("AUTH_MAX_FAILED_ATTEMPTS", "3")
	t.Setenv("AUTH_SECRET_KEY", "a-proper-secret-key-value")
	t.Setenv("CLI_COLOR", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if want := "postgres://app:s3cret@db:5432/logins?sslmode=disable"; cfg.Database.DSN != want {
		t.Errorf("dsn = %q, want %q", cfg.Database.DSN, want)
	}
	if cfg.Auth.SessionIdleTimeout != 45*time.Second {
		t.Errorf("session timeout = %s, want 45s", cfg.Auth.SessionIdleTimeout)
	}
	if cfg.Auth.MaxFailedAttempts != 3 {
		t.Errorf("max failed attempts = %d, want 3", cfg.Auth.MaxFailedAttempts)
	}
	if cfg.CLI.Color {
		t.Error("colour should be off when CLI_COLOR=false")
	}
	if cfg.UsesSampleSecret() {
		t.Error("a custom secret key must not be reported as the sample one")
	}
}

func TestDatabaseURLWins(t *testing.T) {
	clearEnvironment(t)

	t.Setenv("DATABASE_URL", "postgres://user:pw@example.com:6432/prod?sslmode=require")
	t.Setenv("DB_HOST", "ignored")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != "postgres://user:pw@example.com:6432/prod?sslmode=require" {
		t.Errorf("dsn = %q, want the DATABASE_URL value", cfg.Database.DSN)
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	clearEnvironment(t)

	t.Setenv("AUTH_BCRYPT_COST", "4")
	t.Setenv("AUTH_MIN_PASSWORD_LENGTH", "4")
	t.Setenv("AUTH_LOCKOUT_DURATION", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("expected the invalid configuration to be rejected")
	}
	for _, want := range []string{"AUTH_BCRYPT_COST", "AUTH_MIN_PASSWORD_LENGTH", "AUTH_LOCKOUT_DURATION"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s:\n%v", want, err)
		}
	}
}

func TestValidateRejectsASessionCeilingBelowTheIdleTimeout(t *testing.T) {
	cfg := Config{
		Database: Database{DSN: "postgres://localhost/db"},
		Auth: Auth{
			BcryptCost:         12,
			MinPasswordLength:  10,
			MaxPasswordLength:  72,
			MaxFailedAttempts:  5,
			LockoutDuration:    time.Minute,
			SessionIdleTimeout: time.Hour,
			SessionMaxLifetime: time.Minute,
			TOTPChallengeTTL:   time.Minute,
			TOTPIssuer:         "issuer",
			SecretKey:          "a-proper-secret-key-value",
		},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "AUTH_SESSION_MAX_LIFETIME") {
		t.Fatalf("err = %v, want a complaint about AUTH_SESSION_MAX_LIFETIME", err)
	}
}

func TestRedactedHidesThePassword(t *testing.T) {
	db := Database{DSN: "postgres://app:s3cret@db:5432/logins?sslmode=disable"}

	redacted := db.Redacted()
	if strings.Contains(redacted, "s3cret") {
		t.Fatalf("redacted dsn still contains the password: %q", redacted)
	}
	if !strings.Contains(redacted, "app") {
		t.Errorf("redacted dsn = %q, want the username kept", redacted)
	}
}

// clearEnvironment removes every variable the loader reads so a test starts from
// a known state. t.Setenv restores the originals when the test finishes.
func clearEnvironment(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"DATABASE_URL", "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSLMODE",
		"DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS", "DB_CONN_MAX_LIFETIME", "DB_CONNECT_TIMEOUT",
		"AUTH_BCRYPT_COST", "AUTH_MIN_PASSWORD_LENGTH", "AUTH_MAX_FAILED_ATTEMPTS",
		"AUTH_LOCKOUT_DURATION", "AUTH_SESSION_TIMEOUT", "AUTH_SESSION_MAX_LIFETIME",
		"AUTH_TOTP_CHALLENGE_TTL", "AUTH_TOTP_SKEW_PERIODS", "AUTH_TOTP_ISSUER", "AUTH_SECRET_KEY",
		"CLI_HISTORY_FILE", "CLI_HISTORY_LIMIT", "CLI_COLOR", "NO_COLOR",
	} {
		t.Setenv(key, "")
	}
}
