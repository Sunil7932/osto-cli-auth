// Package cli is the interactive front end: a small REPL with history, tab
// completion and one type per command.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// Shell reads commands and dispatches them. It also owns the two cross cutting
// concerns of the front end: revalidating the session before every privileged
// command, and turning service errors into sentences a user can act on.
type Shell struct {
	service  *auth.Service
	registry *Registry
	state    *State
	prompt   Prompter
	out      *Printer
	clock    clock.Clock
	version  string

	quit bool
}

// ShellOptions are the collaborators of the shell.
type ShellOptions struct {
	Service  *auth.Service
	Registry *Registry
	State    *State
	Prompter Prompter
	Printer  *Printer
	Clock    clock.Clock
	Version  string
}

func NewShell(opts ShellOptions) (*Shell, error) {
	if opts.Service == nil || opts.Registry == nil || opts.State == nil || opts.Prompter == nil || opts.Printer == nil || opts.Clock == nil {
		return nil, errors.New("shell is missing collaborators")
	}
	return &Shell{
		service:  opts.Service,
		registry: opts.Registry,
		state:    opts.State,
		prompt:   opts.Prompter,
		out:      opts.Printer,
		clock:    opts.Clock,
		version:  opts.Version,
	}, nil
}

// Run drives the read, dispatch, print loop until the user quits, stdin ends or
// the context is cancelled.
func (s *Shell) Run(ctx context.Context) error {
	s.greet()

	// Reading a line blocks, so a termination signal would otherwise sit unread
	// until the user pressed a key. Closing the prompter unblocks it.
	stopWatching := make(chan struct{})
	defer close(stopWatching)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.prompt.Close()
		case <-stopWatching:
		}
	}()

	for !s.quit {
		if ctx.Err() != nil {
			break
		}

		line, err := s.prompt.ReadLine(s.promptText())
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			switch {
			case errors.Is(err, ErrAborted):
				s.out.Hint("press Ctrl-D or type 'exit' to quit")
				continue
			case errors.Is(err, io.EOF):
				s.out.Println()
				return s.shutdown(ctx)
			default:
				return err
			}
		}

		if strings.TrimSpace(line) == "" {
			continue
		}
		s.dispatch(ctx, line)
	}

	return s.shutdown(ctx)
}

// Stop asks the loop to finish after the current command, used by `exit`.
func (s *Shell) Stop() { s.quit = true }

func (s *Shell) dispatch(ctx context.Context, line string) {
	fields := strings.Fields(line)
	name := strings.ToLower(fields[0])
	args := fields[1:]

	command, known := s.registry.Lookup(name)
	if !known {
		s.out.Failure("unknown command %q", name)
		if suggestions := s.registry.Suggest(name, s.state.IsAuthenticated()); len(suggestions) > 0 {
			s.out.Hint("did you mean: %s", strings.Join(suggestions, ", "))
		}
		s.out.Hint("type 'help' to list the available commands")
		return
	}

	// Any cached session is checked before it is used, which is what makes the
	// configured timeout real rather than decorative.
	if s.state.IsAuthenticated() && !s.revalidate(ctx) && command.Scope() == ScopeAuthenticated {
		// The session just died and revalidate already explained it; repeating
		// "you need to log in" would only add noise.
		return
	}

	authenticated := s.state.IsAuthenticated()
	if !inScope(command.Scope(), authenticated) {
		if command.Scope() == ScopeAuthenticated {
			s.out.Failure("'%s' needs an active session, run 'login' first", command.Name())
		} else {
			s.out.Failure("'%s' is not available while logged in as %s", command.Name(), s.state.Username())
			s.out.Hint("run 'logout' first if you want to switch accounts")
		}
		return
	}

	if err := command.Execute(ctx, args); err != nil {
		switch {
		case errors.Is(err, ErrAborted):
			s.out.Warn("cancelled")
		case errors.Is(err, io.EOF):
			s.quit = true
		default:
			s.Report(err)
		}
	}
}

// revalidate refreshes the cached session and reports whether it is still
// usable. A dead session logs the user out on the spot.
func (s *Shell) revalidate(ctx context.Context) bool {
	session, user, err := s.service.ResolveSession(ctx, s.state.Token())
	if err == nil {
		s.state.Refresh(session, user)
		return true
	}

	s.state.Clear()
	if errors.Is(err, auth.ErrSessionExpired) {
		idle, _ := s.service.SessionWindow()
		s.out.Warn("Session ended (inactive for more than %s).", formatDuration(idle))
		s.out.Hint("run 'login' to start a new session")
		return false
	}
	s.Report(err)
	return false
}

// Report turns an error into feedback. Every branch tells the user what
// happened and, where useful, what to do next.
func (s *Shell) Report(err error) {
	var (
		locked *auth.AccountLockedError
		cred   *auth.CredentialError
		code   *auth.TOTPError
	)

	switch {
	case errors.As(err, &locked):
		s.out.Failure("Account temporarily locked after too many failed attempts.")
		s.out.Hint("try again in %s", formatDuration(locked.RetryAfter(s.clock.Now())))

	case errors.As(err, &cred):
		s.out.Failure("Invalid username or password.")
		if cred.RemainingAttempts > 0 && cred.RemainingAttempts <= 2 {
			s.out.Hint("%s left before the account is locked", pluralAttempts(cred.RemainingAttempts))
		}

	case errors.As(err, &code):
		s.out.Failure("That verification code is not valid.")
		s.out.Hint("codes change every 30 seconds, make sure the device clock is accurate")
		if code.RemainingAttempts > 0 && code.RemainingAttempts <= 2 {
			s.out.Hint("%s left before the account is locked", pluralAttempts(code.RemainingAttempts))
		}

	case domain.IsValidation(err):
		s.out.Failure("%s", sentence(err.Error()))

	case errors.Is(err, domain.ErrUsernameTaken):
		s.out.Failure("That username is already registered.")
		s.out.Hint("pick a different one, or run 'login' if the account is yours")

	case errors.Is(err, auth.ErrSessionExpired):
		s.out.Failure("Your session is no longer valid.")
		s.out.Hint("run 'login' to start a new session")

	case errors.Is(err, auth.ErrChallengeExpired):
		s.out.Failure("The two factor prompt timed out.")
		s.out.Hint("run 'login' again")

	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		s.out.Failure("Two factor authentication is already enabled on this account.")

	case errors.Is(err, auth.ErrTOTPNotEnabled):
		s.out.Failure("Two factor authentication is not enabled on this account.")
		s.out.Hint("run 'enable-2fa' to set it up")

	case errors.Is(err, auth.ErrNoPendingEnrollment):
		s.out.Failure("There is no pending two factor setup to confirm.")
		s.out.Hint("run 'enable-2fa' to start again")

	case errors.Is(err, auth.ErrInvalidTOTPCode):
		s.out.Failure("That verification code is not valid.")

	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.out.Failure("The request was cancelled.")

	default:
		s.out.Failure("Something went wrong: %v", err)
	}
}

func (s *Shell) shutdown(ctx context.Context) error {
	if s.state.IsAuthenticated() {
		// Revoking the session still has to happen when we are here because the
		// context was cancelled, so it gets a detached one with a short budget.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		if err := s.service.Logout(ctx, s.state.Token()); err != nil {
			s.out.Warn("could not revoke the session cleanly: %v", err)
		} else {
			s.out.Info("Session for %s ended.", s.state.Username())
		}
		s.state.Clear()
	}
	s.out.Info("Bye.")
	return nil
}

func (s *Shell) greet() {
	s.out.Printf("%s\n", s.out.paint(ansiBold, fmt.Sprintf("authcli %s", s.version)))
	s.out.Info("Secure login shell. Type 'help' for the command list, 'exit' to quit.")
	if !s.prompt.Interactive() {
		s.out.Hint("stdin is not a terminal: history and tab completion are disabled")
	}
	s.out.Println()
}

func (s *Shell) promptText() string {
	name := s.state.Username()
	if s.state.IsAuthenticated() {
		return fmt.Sprintf("authcli(%s)> ", s.out.paint(ansiGreen, name))
	}
	return fmt.Sprintf("authcli(%s)> ", s.out.paint(ansiDim, name))
}

func pluralAttempts(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}

// sentence upper cases the first letter and adds a full stop, so validation
// messages written as fragments still read as sentences.
func sentence(text string) string {
	if text == "" {
		return text
	}
	runes := []rune(text)
	runes[0] = unicode.ToUpper(runes[0])
	out := string(runes)
	if !strings.HasSuffix(out, ".") {
		out += "."
	}
	return out
}
