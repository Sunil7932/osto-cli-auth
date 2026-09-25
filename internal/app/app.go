// Package app is the composition root: it is the only place that knows about
// every layer at once and wires them together.
package app

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/cli"
	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/config"
	"github.com/Sunil7932/cli-login-2fa/internal/storage/postgres"
)

// App owns the process wide resources and the shell built on top of them.
type App struct {
	cfg      config.Config
	db       *sql.DB
	service  *auth.Service
	shell    *cli.Shell
	prompter cli.Prompter
	printer  *cli.Printer
}

// New connects to the database, applies pending migrations and assembles the
// object graph.
func New(ctx context.Context, cfg config.Config, version string) (*App, error) {
	printer := cli.NewPrinter(os.Stdout, cfg.CLI.Color)

	db, err := postgres.Open(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	app := &App{cfg: cfg, db: db, printer: printer}

	applied, err := postgres.Migrate(ctx, db)
	if err != nil {
		app.closeDB()
		return nil, err
	}
	for _, migration := range applied {
		printer.Info("applied migration %04d_%s", migration.Version, migration.Name)
	}

	service, err := buildService(cfg, db)
	if err != nil {
		app.closeDB()
		return nil, err
	}
	app.service = service

	if removed, err := service.PurgeExpiredSessions(ctx); err != nil {
		printer.Warn("could not prune expired sessions: %v", err)
	} else if removed > 0 {
		printer.Hint("pruned %d expired session(s)", removed)
	}

	if cfg.UsesSampleSecret() {
		printer.Warn("AUTH_SECRET_KEY is still the sample value from .env.example")
		printer.Hint("set your own key before using this with real accounts")
	}

	state := cli.NewState()
	registry := cli.NewRegistry()

	prompter, err := cli.NewPrompter(cli.PrompterOptions{
		HistoryFile:  cfg.CLI.HistoryFile,
		HistoryLimit: cfg.CLI.HistoryLimit,
		Completer:    cli.NewCompleter(registry, state),
		Output:       os.Stdout,
	})
	if err != nil {
		app.closeDB()
		return nil, err
	}
	app.prompter = prompter

	deps := cli.Deps{
		Service:  service,
		State:    state,
		Prompter: prompter,
		Printer:  printer,
		Clock:    clock.System(),
	}

	shell, err := cli.NewShell(cli.ShellOptions{
		Service:  service,
		Registry: registry,
		State:    state,
		Prompter: prompter,
		Printer:  printer,
		Clock:    clock.System(),
		Version:  version,
	})
	if err != nil {
		app.Close()
		return nil, err
	}
	if err := cli.RegisterCommands(registry, deps, shell); err != nil {
		app.Close()
		return nil, err
	}
	app.shell = shell

	return app, nil
}

// Run starts the interactive shell.
func (a *App) Run(ctx context.Context) error {
	return a.shell.Run(ctx)
}

// Close releases the prompter (restoring the terminal) and the database pool.
func (a *App) Close() error {
	if a.prompter != nil {
		_ = a.prompter.Close()
	}
	return a.closeDB()
}

func (a *App) closeDB() error {
	if a.db == nil {
		return nil
	}
	if err := a.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	a.db = nil
	return nil
}

// buildService picks the concrete adapters for the auth service. Swapping the
// storage backend or the hashing algorithm happens here and nowhere else.
func buildService(cfg config.Config, db *sql.DB) (*auth.Service, error) {
	hasher, err := auth.NewBcryptHasher(cfg.Auth.BcryptCost)
	if err != nil {
		return nil, err
	}
	cipher, err := auth.NewAESGCMCipher(cfg.Auth.SecretKey)
	if err != nil {
		return nil, err
	}

	systemClock := clock.System()

	return auth.NewService(
		auth.Dependencies{
			Users:      postgres.NewUserRepository(db),
			Sessions:   postgres.NewSessionRepository(db),
			Events:     postgres.NewEventRepository(db),
			Tx:         postgres.NewTxManager(db),
			Hasher:     hasher,
			TOTP:       auth.NewGoogleAuthenticator(cfg.Auth.TOTPIssuer, cfg.Auth.TOTPSkewPeriods),
			Cipher:     cipher,
			Challenges: auth.NewMemoryChallengeStore(systemClock),
			Clock:      systemClock,
		},
		auth.WithPasswordPolicy(auth.PasswordPolicy{
			MinLength: cfg.Auth.MinPasswordLength,
			MaxLength: cfg.Auth.MaxPasswordLength,
		}),
		auth.WithLockoutPolicy(auth.LockoutPolicy{
			MaxAttempts: cfg.Auth.MaxFailedAttempts,
			Duration:    cfg.Auth.LockoutDuration,
		}),
		auth.WithSessionWindow(cfg.Auth.SessionIdleTimeout, cfg.Auth.SessionMaxLifetime),
		auth.WithChallengeTTL(cfg.Auth.TOTPChallengeTTL),
	)
}
