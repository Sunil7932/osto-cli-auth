// Package config loads runtime settings from the environment.
//
// Everything has a sane default so the binary can start with an empty
// environment during development, but values that are unsafe in production
// (for example the sample secret key) are reported by Validate.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// SampleSecretKey is the value shipped in .env.example. It exists so we can
// warn operators who never rotated it.
const SampleSecretKey = "change-me-in-production"

type Config struct {
	Database Database
	Auth     Auth
	CLI      CLI
}

type Database struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	// ConnectTimeout bounds the startup wait for the database container to
	// accept connections. Compose healthchecks help, but a retry loop keeps
	// `docker compose run` usable on cold starts.
	ConnectTimeout time.Duration
}

type Auth struct {
	BcryptCost         int
	MinPasswordLength  int
	MaxPasswordLength  int
	MaxFailedAttempts  int
	LockoutDuration    time.Duration
	SessionIdleTimeout time.Duration
	SessionMaxLifetime time.Duration
	TOTPIssuer         string
	TOTPSkewPeriods    uint
	// TOTPChallengeTTL is how long a password-verified login may wait for the
	// six digit code before the user has to start over.
	TOTPChallengeTTL time.Duration
	// SecretKey encrypts TOTP shared secrets at rest.
	SecretKey string
}

type CLI struct {
	HistoryFile  string
	HistoryLimit int
	Color        bool
}

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	dsn, err := databaseDSN()
	collect(err)

	cfg := Config{
		Database: Database{DSN: dsn},
	}

	cfg.Database.MaxOpenConns, err = envInt("DB_MAX_OPEN_CONNS", 8)
	collect(err)
	cfg.Database.MaxIdleConns, err = envInt("DB_MAX_IDLE_CONNS", 4)
	collect(err)
	cfg.Database.ConnMaxLifetime, err = envDuration("DB_CONN_MAX_LIFETIME", time.Hour)
	collect(err)
	cfg.Database.ConnectTimeout, err = envDuration("DB_CONNECT_TIMEOUT", 30*time.Second)
	collect(err)

	cfg.Auth.BcryptCost, err = envInt("AUTH_BCRYPT_COST", 12)
	collect(err)
	cfg.Auth.MinPasswordLength, err = envInt("AUTH_MIN_PASSWORD_LENGTH", 10)
	collect(err)
	// bcrypt silently ignores anything past the 72nd byte, so that is the
	// hard ceiling rather than an arbitrary product decision.
	cfg.Auth.MaxPasswordLength = 72
	cfg.Auth.MaxFailedAttempts, err = envInt("AUTH_MAX_FAILED_ATTEMPTS", 5)
	collect(err)
	cfg.Auth.LockoutDuration, err = envDuration("AUTH_LOCKOUT_DURATION", 15*time.Minute)
	collect(err)
	cfg.Auth.SessionIdleTimeout, err = envDuration("AUTH_SESSION_TIMEOUT", 15*time.Minute)
	collect(err)
	cfg.Auth.SessionMaxLifetime, err = envDuration("AUTH_SESSION_MAX_LIFETIME", 8*time.Hour)
	collect(err)
	cfg.Auth.TOTPChallengeTTL, err = envDuration("AUTH_TOTP_CHALLENGE_TTL", 2*time.Minute)
	collect(err)
	skew, err := envInt("AUTH_TOTP_SKEW_PERIODS", 1)
	collect(err)
	if skew >= 0 {
		cfg.Auth.TOTPSkewPeriods = uint(skew)
	}
	cfg.Auth.TOTPIssuer = envString("AUTH_TOTP_ISSUER", "osto-cli-auth")
	cfg.Auth.SecretKey = envString("AUTH_SECRET_KEY", SampleSecretKey)

	cfg.CLI.HistoryFile = envString("CLI_HISTORY_FILE", defaultHistoryFile())
	cfg.CLI.HistoryLimit, err = envInt("CLI_HISTORY_LIMIT", 500)
	collect(err)
	cfg.CLI.Color = envBool("CLI_COLOR", os.Getenv("NO_COLOR") == "")

	// Unparsable values fell back to their defaults above, so validating anyway
	// surfaces every problem in one go instead of one per run.
	if err := errors.Join(append(errs, cfg.Validate())...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects combinations that would silently weaken the system.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Database.DSN) == "" {
		errs = append(errs, errors.New("database DSN is empty: set DATABASE_URL or the DB_* variables"))
	}
	// 10 is bcrypt's default; below that hashes get cheap enough to matter.
	if c.Auth.BcryptCost < 10 || c.Auth.BcryptCost > 31 {
		errs = append(errs, fmt.Errorf("AUTH_BCRYPT_COST must be between 10 and 31, got %d", c.Auth.BcryptCost))
	}
	if c.Auth.MinPasswordLength < 8 {
		errs = append(errs, fmt.Errorf("AUTH_MIN_PASSWORD_LENGTH must be at least 8, got %d", c.Auth.MinPasswordLength))
	}
	if c.Auth.MinPasswordLength > c.Auth.MaxPasswordLength {
		errs = append(errs, fmt.Errorf("AUTH_MIN_PASSWORD_LENGTH cannot exceed %d", c.Auth.MaxPasswordLength))
	}
	if c.Auth.MaxFailedAttempts < 1 {
		errs = append(errs, fmt.Errorf("AUTH_MAX_FAILED_ATTEMPTS must be positive, got %d", c.Auth.MaxFailedAttempts))
	}
	if c.Auth.LockoutDuration <= 0 {
		errs = append(errs, errors.New("AUTH_LOCKOUT_DURATION must be positive"))
	}
	if c.Auth.SessionIdleTimeout <= 0 {
		errs = append(errs, errors.New("AUTH_SESSION_TIMEOUT must be positive"))
	}
	if c.Auth.SessionMaxLifetime < c.Auth.SessionIdleTimeout {
		errs = append(errs, errors.New("AUTH_SESSION_MAX_LIFETIME must be greater than or equal to AUTH_SESSION_TIMEOUT"))
	}
	if c.Auth.TOTPChallengeTTL <= 0 {
		errs = append(errs, errors.New("AUTH_TOTP_CHALLENGE_TTL must be positive"))
	}
	if strings.TrimSpace(c.Auth.TOTPIssuer) == "" {
		errs = append(errs, errors.New("AUTH_TOTP_ISSUER must not be empty"))
	}
	if len(c.Auth.SecretKey) < 16 {
		errs = append(errs, errors.New("AUTH_SECRET_KEY must be at least 16 characters"))
	}

	return errors.Join(errs...)
}

// UsesSampleSecret reports whether the shipped example key is still in use.
func (c Config) UsesSampleSecret() bool {
	return c.Auth.SecretKey == SampleSecretKey
}

// Redacted returns the DSN with the password removed, safe for logs.
func (d Database) Redacted() string {
	u, err := url.Parse(d.DSN)
	if err != nil || u.User == nil {
		return d.DSN
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

func databaseDSN() (string, error) {
	if dsn := envString("DATABASE_URL", ""); dsn != "" {
		return dsn, nil
	}

	host := envString("DB_HOST", "localhost")
	user := envString("DB_USER", "authcli")
	password := envString("DB_PASSWORD", "")
	name := envString("DB_NAME", "authcli")
	sslMode := envString("DB_SSLMODE", "disable")

	port, err := envInt("DB_PORT", 5432)
	if err != nil {
		return "", err
	}

	dsn := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + name,
	}
	if password == "" {
		dsn.User = url.User(user)
	} else {
		dsn.User = url.UserPassword(user, password)
	}
	dsn.RawQuery = url.Values{"sslmode": {sslMode}}.Encode()

	return dsn.String(), nil
}

func defaultHistoryFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".authcli_history"
	}
	return home + "/.authcli_history"
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return v, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s must be a duration such as 15m or 2h: %w", key, err)
	}
	return v, nil
}

func envBool(key string, fallback bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}
