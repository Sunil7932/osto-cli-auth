// Command authcli is the interactive login shell described in the README.
//
// Usage:
//
//	authcli                 start the interactive shell (default)
//	authcli migrate         apply pending database migrations and exit
//	authcli migrate-status  show which migrations have run
//	authcli version         print the build version
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sunil7932/cli-login-2fa/internal/app"
	"github.com/Sunil7932/cli-login-2fa/internal/config"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, context.Canceled) {
			// Terminated by a signal; not a failure worth a stack of text.
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "authcli: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "shell"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "version", "--version", "-v":
		fmt.Printf("authcli %s\n", version)
		return nil
	case "help", "--help", "-h":
		usage(os.Stdout)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration is invalid:\n%w", err)
	}

	// Ctrl-C is handled by the line editor so it can cancel a prompt instead of
	// the process. A real termination signal still has to shut us down.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	switch command {
	case "shell":
		return runShell(ctx, cfg)
	case "migrate":
		return app.Migrate(ctx, cfg)
	case "migrate-status":
		return app.MigrationStatus(ctx, cfg)
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

func runShell(ctx context.Context, cfg config.Config) error {
	application, err := app.New(ctx, cfg, version)
	if err != nil {
		return err
	}
	defer func() {
		if err := application.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "authcli: %v\n", err)
		}
	}()

	return application.Run(ctx)
}

func usage(out *os.File) {
	fmt.Fprint(out, `authcli - containerized CLI login system

Commands:
  (none)          start the interactive shell
  migrate         apply pending database migrations
  migrate-status  list migrations and whether they have run
  version         print the build version
  help            print this message

Configuration comes from the environment, see .env.example for the full list.
`)
}
