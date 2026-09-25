package cli

import (
	"github.com/chzyer/readline"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
	"github.com/Sunil7932/cli-login-2fa/internal/clock"
)

// Deps are the collaborators shared by every command. Passing one struct keeps
// the command constructors short and makes it obvious that commands own no
// state of their own.
type Deps struct {
	Service  *auth.Service
	State    *State
	Prompter Prompter
	Printer  *Printer
	Clock    clock.Clock
}

// NewCompleter builds the tab completion source. It reads the registry through
// closures so the candidate list follows the login state.
func NewCompleter(registry *Registry, state *State) readline.AutoCompleter {
	return &commandCompleter{
		names: func() []string {
			return registry.Names(state.IsAuthenticated())
		},
	}
}

// RegisterCommands wires the command set into the registry. The shell is passed
// in because `exit` has to be able to stop the loop and `help` needs to know
// what is registered.
func RegisterCommands(registry *Registry, deps Deps, shell *Shell) error {
	return registry.Register(
		newRegisterCommand(deps),
		newLoginCommand(deps),
		newWhoAmICommand(deps),
		newEnable2FACommand(deps),
		newDisable2FACommand(deps),
		newActivityCommand(deps),
		newLogoutCommand(deps),
		newHelpCommand(deps, registry),
		newExitCommand(deps, shell),
	)
}
