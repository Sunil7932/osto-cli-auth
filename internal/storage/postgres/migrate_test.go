package postgres

import (
	"strings"
	"testing"
)

func TestAvailableMigrationsAreOrderedAndNamed(t *testing.T) {
	migrations, err := AvailableMigrations()
	if err != nil {
		t.Fatalf("available migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("expected the migrations to be embedded in the binary")
	}

	for i, migration := range migrations {
		if migration.Version != i+1 {
			t.Errorf("migration %d has version %d, want %d (versions must be contiguous)", i, migration.Version, i+1)
		}
		if migration.Name == "" {
			t.Errorf("migration %04d has no name", migration.Version)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			t.Errorf("migration %04d_%s is empty", migration.Version, migration.Name)
		}
	}

	if first := migrations[0]; first.Name != "init" || !strings.Contains(first.SQL, "CREATE TABLE users") {
		t.Errorf("first migration = %04d_%s, want it to create the users table", first.Version, first.Name)
	}
}

func TestParseMigrationName(t *testing.T) {
	version, name, err := parseMigrationName("0007_add_totp.sql")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if version != 7 || name != "add_totp" {
		t.Errorf("got %d, %q, want 7, add_totp", version, name)
	}

	for _, filename := range []string{"init.sql", "abc_init.sql"} {
		if _, _, err := parseMigrationName(filename); err == nil {
			t.Errorf("parseMigrationName(%q) = nil error, want a failure", filename)
		}
	}
}
