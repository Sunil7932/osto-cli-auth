package cli

import (
	"context"
	"fmt"
	"strings"
)

// helpCommand lists what can be run right now, or explains one command.
type helpCommand struct {
	baseCommand
	deps     Deps
	registry *Registry
}

func newHelpCommand(deps Deps, registry *Registry) Command {
	return &helpCommand{
		baseCommand: baseCommand{
			name:    "help",
			aliases: []string{"?"},
			summary: "list the available commands",
			usage:   "help [command]",
			scope:   ScopeAlways,
		},
		deps:     deps,
		registry: registry,
	}
}

func (c *helpCommand) Execute(_ context.Context, args []string) error {
	out := c.deps.Printer
	authenticated := c.deps.State.IsAuthenticated()

	if len(args) > 0 {
		name := strings.ToLower(args[0])
		command, ok := c.registry.Lookup(name)
		if !ok {
			out.Failure("unknown command %q", name)
			return nil
		}
		out.Heading(command.Name())
		rows := [][2]string{
			{"Purpose", command.Summary()},
			{"Usage", command.Usage()},
			{"Available", describeScope(command.Scope())},
		}
		if len(command.Aliases()) > 0 {
			rows = append(rows, [2]string{"Aliases", strings.Join(command.Aliases(), ", ")})
		}
		out.KeyValues(rows)
		return nil
	}

	if authenticated {
		out.Heading(fmt.Sprintf("Commands (signed in as %s)", c.deps.State.Username()))
	} else {
		out.Heading("Commands (not signed in)")
	}

	commands := c.registry.Available(authenticated)
	rows := make([][2]string, 0, len(commands))
	for _, command := range commands {
		rows = append(rows, [2]string{command.Name(), command.Summary()})
	}
	out.KeyValues(rows)

	out.Println()
	if c.deps.Prompter.Interactive() {
		out.Hint("Tab completes commands, the up arrow walks through history")
	}
	out.Hint("'help <command>' explains a single command")
	return nil
}

func describeScope(scope Scope) string {
	switch scope {
	case ScopeGuest:
		return "before login"
	case ScopeAuthenticated:
		return "while signed in"
	default:
		return "always"
	}
}

// exitCommand stops the shell. Leaving also revokes the session, which the
// shell does during shutdown.
type exitCommand struct {
	baseCommand
	deps  Deps
	shell *Shell
}

func newExitCommand(deps Deps, shell *Shell) Command {
	return &exitCommand{
		baseCommand: baseCommand{
			name:    "exit",
			aliases: []string{"quit"},
			summary: "quit the program",
			usage:   "exit",
			scope:   ScopeAlways,
		},
		deps:  deps,
		shell: shell,
	}
}

func (c *exitCommand) Execute(_ context.Context, _ []string) error {
	c.shell.Stop()
	return nil
}
