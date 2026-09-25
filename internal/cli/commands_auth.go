package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// registerCommand creates an account.
type registerCommand struct {
	baseCommand
	deps Deps
}

func newRegisterCommand(deps Deps) Command {
	return &registerCommand{
		baseCommand: baseCommand{
			name:    "register",
			summary: "create a new account",
			usage:   "register [username]",
			scope:   ScopeGuest,
		},
		deps: deps,
	}
}

func (c *registerCommand) Execute(ctx context.Context, args []string) error {
	out := c.deps.Printer
	policy := c.deps.Service.PasswordPolicy()

	out.Heading("Create an account")
	out.Hint("username: %d-%d characters, letters, digits, dot, underscore or hyphen",
		domain.UsernameMinLength, domain.UsernameMaxLength)
	out.Hint("password: at least %d characters, mixing letters with a digit or symbol", policy.MinLength)

	username, err := c.resolveUsername(args)
	if err != nil {
		return err
	}

	password, err := c.deps.Prompter.ReadSecret("Password: ")
	if err != nil {
		return err
	}
	confirmation, err := c.deps.Prompter.ReadSecret("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return &domain.ValidationError{Field: "password", Message: "confirmation did not match"}
	}

	user, err := c.deps.Service.Register(ctx, username, password)
	if err != nil {
		return err
	}

	out.Success("Account '%s' created on %s.", user.Username, formatTime(&user.CreatedAt))
	out.Hint("run 'login' to sign in, then 'enable-2fa' to add an authenticator app")
	return nil
}

func (c *registerCommand) resolveUsername(args []string) (string, error) {
	if len(args) > 0 {
		c.deps.Printer.Info("Username: %s", args[0])
		return args[0], nil
	}
	return c.deps.Prompter.ReadLine("Username: ")
}

// loginCommand performs the password step and, when the account has two factor
// enabled, the code step as well.
type loginCommand struct {
	baseCommand
	deps Deps
}

func newLoginCommand(deps Deps) Command {
	return &loginCommand{
		baseCommand: baseCommand{
			name:    "login",
			summary: "sign in with username and password",
			usage:   "login [username]",
			scope:   ScopeGuest,
		},
		deps: deps,
	}
}

func (c *loginCommand) Execute(ctx context.Context, args []string) error {
	out := c.deps.Printer

	var (
		username string
		err      error
	)
	if len(args) > 0 {
		username = args[0]
		out.Info("Username: %s", username)
	} else {
		username, err = c.deps.Prompter.ReadLine("Username: ")
		if err != nil {
			return err
		}
	}

	password, err := c.deps.Prompter.ReadSecret("Password: ")
	if err != nil {
		return err
	}

	result, err := c.deps.Service.Authenticate(ctx, auth.AuthenticateRequest{
		Username:   username,
		Password:   password,
		ClientInfo: clientInfo(),
	})
	if err != nil {
		return err
	}

	if result.Status == auth.StatusTOTPRequired {
		result, err = c.completeTwoFactor(ctx, result)
		if err != nil {
			return err
		}
		if result == nil {
			// The user gave up at the code prompt.
			return nil
		}
	}

	c.deps.State.Set(result.Token, result.Session, result.User)

	out.Success("Signed in as %s.", result.User.Username)
	renderAccount(out, accountView{
		user:      result.User,
		session:   result.Session,
		lastLogin: result.PreviousLoginAt,
		now:       c.deps.Clock.Now(),
	})
	if !result.User.TOTPEnabled {
		out.Hint("two factor authentication is off, 'enable-2fa' takes about a minute to set up")
	}
	return nil
}

// completeTwoFactor prompts for codes until one is accepted, the user cancels or
// the service gives up on the challenge.
func (c *loginCommand) completeTwoFactor(ctx context.Context, pending *auth.Result) (*auth.Result, error) {
	out := c.deps.Printer
	out.Info("Two factor authentication is enabled for this account.")

	for {
		code, err := c.deps.Prompter.ReadLine("Authenticator code: ")
		if err != nil {
			if errors.Is(err, ErrAborted) {
				c.deps.Service.AbandonChallenge(ctx, pending.ChallengeID)
			}
			return nil, err
		}
		if strings.TrimSpace(code) == "" {
			c.deps.Service.AbandonChallenge(ctx, pending.ChallengeID)
			out.Warn("Login cancelled.")
			return nil, nil
		}

		result, err := c.deps.Service.CompleteTOTPChallenge(ctx, pending.ChallengeID, code, clientInfo())
		if err == nil {
			return result, nil
		}

		var invalid *auth.TOTPError
		if !errors.As(err, &invalid) {
			return nil, err
		}
		out.Failure("That code is not valid.")
		if invalid.RemainingAttempts > 0 && invalid.RemainingAttempts <= 2 {
			out.Hint("%s left before the account is locked", pluralAttempts(invalid.RemainingAttempts))
		}
		out.Hint("wait for the next code and try again, or press Enter to cancel")
	}
}

// clientInfo is stored with the session so the audit trail shows where a login
// came from.
func clientInfo() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown-host"
	}
	return fmt.Sprintf("cli %s/pid-%d", host, os.Getpid())
}
