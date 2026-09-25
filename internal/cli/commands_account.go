package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// maxCodePrompts caps how many times the CLI asks for a code before giving up,
// so a mistyped setup does not turn into an endless loop.
const maxCodePrompts = 3

// whoAmICommand prints the details of the logged in account.
type whoAmICommand struct {
	baseCommand
	deps Deps
}

func newWhoAmICommand(deps Deps) Command {
	return &whoAmICommand{
		baseCommand: baseCommand{
			name:    "whoami",
			aliases: []string{"me"},
			summary: "show the current user and session",
			usage:   "whoami",
			scope:   ScopeAuthenticated,
		},
		deps: deps,
	}
}

func (c *whoAmICommand) Execute(_ context.Context, _ []string) error {
	user := c.deps.State.User()
	session := c.deps.State.Session()

	renderAccount(c.deps.Printer, accountView{
		user:      user,
		session:   session,
		lastLogin: user.LastLoginAt,
		now:       c.deps.Clock.Now(),
	})
	return nil
}

// enable2FACommand walks the user through TOTP enrollment.
type enable2FACommand struct {
	baseCommand
	deps Deps
}

func newEnable2FACommand(deps Deps) Command {
	return &enable2FACommand{
		baseCommand: baseCommand{
			name:    "enable-2fa",
			summary: "turn on TOTP two factor authentication",
			usage:   "enable-2fa",
			scope:   ScopeAuthenticated,
		},
		deps: deps,
	}
}

func (c *enable2FACommand) Execute(ctx context.Context, _ []string) error {
	out := c.deps.Printer
	user := c.deps.State.User()

	enrollment, err := c.deps.Service.BeginTOTPEnrollment(ctx, user.ID)
	if err != nil {
		return err
	}

	out.Heading("Set up two factor authentication")
	out.Info("1. Scan this code with Google Authenticator, Authy, 1Password or similar:")
	out.Println()
	qrterminal.GenerateHalfBlock(enrollment.URI, qrterminal.L, out.Writer())
	out.Info("   Cannot scan it? Add the account by hand with this secret:")
	out.Info("   %s", enrollment.Secret)
	out.Println()
	out.Info("2. Enter the current 6 digit code to finish. Press Enter to cancel.")

	for attempt := 1; attempt <= maxCodePrompts; attempt++ {
		code, err := c.deps.Prompter.ReadLine("Code: ")
		if err != nil {
			if errors.Is(err, ErrAborted) {
				_ = c.deps.Service.CancelTOTPEnrollment(ctx, user.ID)
			}
			return err
		}
		if strings.TrimSpace(code) == "" {
			if err := c.deps.Service.CancelTOTPEnrollment(ctx, user.ID); err != nil {
				return err
			}
			out.Warn("Setup cancelled, two factor authentication stays off.")
			return nil
		}

		err = c.deps.Service.ConfirmTOTPEnrollment(ctx, user.ID, code, sessionID(c.deps.State))
		if err == nil {
			refreshUser(ctx, c.deps)
			out.Success("Two factor authentication is now enabled.")
			out.Hint("the next login will ask for a code from this device")
			out.Hint("keep the secret above somewhere safe, losing the device means losing access")
			return nil
		}
		if !errors.Is(err, auth.ErrInvalidTOTPCode) {
			return err
		}
		out.Failure("That code did not match (attempt %d of %d).", attempt, maxCodePrompts)
		out.Hint("wait for the app to show the next code, then type it in")
	}

	if err := c.deps.Service.CancelTOTPEnrollment(ctx, user.ID); err != nil {
		return err
	}
	out.Failure("Too many invalid codes, setup abandoned.")
	out.Hint("check that the device clock is correct and run 'enable-2fa' again")
	return nil
}

// disable2FACommand removes the second factor, but only for someone who can
// still produce a valid code.
type disable2FACommand struct {
	baseCommand
	deps Deps
}

func newDisable2FACommand(deps Deps) Command {
	return &disable2FACommand{
		baseCommand: baseCommand{
			name:    "disable-2fa",
			summary: "turn off TOTP two factor authentication",
			usage:   "disable-2fa",
			scope:   ScopeAuthenticated,
		},
		deps: deps,
	}
}

func (c *disable2FACommand) Execute(ctx context.Context, _ []string) error {
	out := c.deps.Printer
	user := c.deps.State.User()

	if !user.TOTPEnabled {
		return auth.ErrTOTPNotEnabled
	}

	out.Warn("Disabling two factor authentication makes the account password only.")
	out.Info("Enter a current code to confirm, or press Enter to keep it enabled.")

	for attempt := 1; attempt <= maxCodePrompts; attempt++ {
		code, err := c.deps.Prompter.ReadLine("Code: ")
		if err != nil {
			return err
		}
		if strings.TrimSpace(code) == "" {
			out.Info("Two factor authentication stays enabled.")
			return nil
		}

		err = c.deps.Service.DisableTOTP(ctx, user.ID, code, sessionID(c.deps.State))
		if err == nil {
			refreshUser(ctx, c.deps)
			out.Success("Two factor authentication is now disabled.")
			out.Hint("run 'enable-2fa' whenever you want to turn it back on")
			return nil
		}
		if !errors.Is(err, auth.ErrInvalidTOTPCode) {
			return err
		}
		out.Failure("That code is not valid (attempt %d of %d).", attempt, maxCodePrompts)
	}

	out.Failure("Too many invalid codes, two factor authentication stays enabled.")
	return nil
}

// activityCommand shows the audit trail of the account.
type activityCommand struct {
	baseCommand
	deps Deps
}

func newActivityCommand(deps Deps) Command {
	return &activityCommand{
		baseCommand: baseCommand{
			name:    "activity",
			summary: "list recent security events for this account",
			usage:   "activity [count]",
			scope:   ScopeAuthenticated,
		},
		deps: deps,
	}
}

func (c *activityCommand) Execute(ctx context.Context, args []string) error {
	out := c.deps.Printer
	limit := 10
	if len(args) > 0 {
		parsed, err := parsePositiveInt(args[0])
		if err != nil {
			return &domain.ValidationError{Field: "count", Message: "must be a positive number"}
		}
		limit = min(parsed, 50)
	}

	events, err := c.deps.Service.RecentActivity(ctx, c.deps.State.User().ID, limit)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		out.Info("No activity recorded yet.")
		return nil
	}

	out.Heading(fmt.Sprintf("Last %d events", len(events)))
	rows := make([][2]string, 0, len(events))
	for _, event := range events {
		when := event.CreatedAt
		label := when.Local().Format("2006-01-02 15:04:05")
		description := string(event.Type)
		if event.Detail != "" {
			description = fmt.Sprintf("%s (%s)", description, event.Detail)
		}
		rows = append(rows, [2]string{label, description})
	}
	out.KeyValues(rows)
	return nil
}

// logoutCommand ends the current session.
type logoutCommand struct {
	baseCommand
	deps Deps
}

func newLogoutCommand(deps Deps) Command {
	return &logoutCommand{
		baseCommand: baseCommand{
			name:    "logout",
			summary: "end the current session",
			usage:   "logout",
			scope:   ScopeAuthenticated,
		},
		deps: deps,
	}
}

func (c *logoutCommand) Execute(ctx context.Context, _ []string) error {
	username := c.deps.State.Username()
	if err := c.deps.Service.Logout(ctx, c.deps.State.Token()); err != nil {
		return err
	}
	c.deps.State.Clear()
	c.deps.Printer.Success("Logged out %s.", username)
	return nil
}

// accountView is everything the account summary needs.
type accountView struct {
	user    *domain.User
	session *domain.Session
	// lastLogin is shown as "Last login". After a fresh login this is the
	// previous one, which is the value that actually tells a user something.
	lastLogin *time.Time
	now       time.Time
}

// renderAccount prints the block shown right after login and by whoami.
func renderAccount(out *Printer, view accountView) {
	expiry := view.session.ExpiresAt()

	rows := [][2]string{
		{"Username", view.user.Username},
		{"Registered", formatTime(&view.user.CreatedAt)},
		{"Two factor", describeMFA(view.user)},
		{"Session started", formatTime(&view.session.IssuedAt)},
		{"Session expires", fmt.Sprintf("%s (in %s)", formatTime(&expiry), formatDuration(view.session.TimeLeft(view.now)))},
		{"Last login", formatTime(view.lastLogin)},
	}

	out.Heading("Account")
	out.KeyValues(rows)
	out.Println()
}

func sessionID(state *State) int64 {
	if state == nil || state.Session() == nil {
		return 0
	}
	return state.Session().ID
}

// refreshUser pulls the latest row so whoami/help reflect 2FA changes without
// waiting for the next command to revalidate the session.
func refreshUser(ctx context.Context, deps Deps) {
	if !deps.State.IsAuthenticated() {
		return
	}
	session, user, err := deps.Service.ResolveSession(ctx, deps.State.Token())
	if err != nil {
		return
	}
	deps.State.Refresh(session, user)
}

func describeMFA(user *domain.User) string {
	switch {
	case user.TOTPEnabled && user.TOTPConfirmedAt != nil:
		return fmt.Sprintf("enabled (since %s)", formatTime(user.TOTPConfirmedAt))
	case user.TOTPEnabled:
		return "enabled"
	case user.HasPendingTOTPEnrollment():
		return "disabled (setup started but never confirmed)"
	default:
		return "disabled"
	}
}

func parsePositiveInt(raw string) (int, error) {
	value := 0
	if raw == "" {
		return 0, errors.New("empty number")
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
		value = value*10 + int(r-'0')
		if value > 1000 {
			return 1000, nil
		}
	}
	if value == 0 {
		return 0, errors.New("zero is not allowed")
	}
	return value, nil
}
