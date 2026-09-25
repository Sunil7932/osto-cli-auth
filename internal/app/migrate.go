package app

import (
	"context"
	"fmt"
	"os"

	"github.com/Sunil7932/cli-login-2fa/internal/cli"
	"github.com/Sunil7932/cli-login-2fa/internal/config"
	"github.com/Sunil7932/cli-login-2fa/internal/storage/postgres"
)

// Migrate applies pending migrations without starting the shell. The startup
// path does this automatically; the subcommand exists for CI and for operators
// who want to migrate before rolling out a new binary.
func Migrate(ctx context.Context, cfg config.Config) error {
	printer := cli.NewPrinter(os.Stdout, cfg.CLI.Color)

	db, err := postgres.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()

	applied, err := postgres.Migrate(ctx, db)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		printer.Success("Schema already up to date.")
		return nil
	}
	for _, migration := range applied {
		printer.Success("applied %04d_%s", migration.Version, migration.Name)
	}
	return nil
}

// MigrationStatus lists the embedded migrations and whether they ran.
func MigrationStatus(ctx context.Context, cfg config.Config) error {
	printer := cli.NewPrinter(os.Stdout, cfg.CLI.Color)

	available, err := postgres.AvailableMigrations()
	if err != nil {
		return err
	}

	db, err := postgres.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()

	applied, err := postgres.Applied(ctx, db)
	if err != nil {
		return err
	}
	appliedAt := make(map[int]string, len(applied))
	for _, record := range applied {
		appliedAt[record.Version] = record.AppliedAt.Local().Format("2006-01-02 15:04:05")
	}

	printer.Heading("Migrations")
	rows := make([][2]string, 0, len(available))
	for _, migration := range available {
		status := "pending"
		if when, ok := appliedAt[migration.Version]; ok {
			status = "applied " + when
		}
		rows = append(rows, [2]string{fmt.Sprintf("%04d_%s", migration.Version, migration.Name), status})
	}
	printer.KeyValues(rows)
	return nil
}
