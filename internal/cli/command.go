package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Scope decides when a command is offered. The shell uses it both for the help
// listing and for tab completion, so a logged out user never sees commands they
// cannot run.
type Scope int

const (
	// ScopeAlways is available logged in or not.
	ScopeAlways Scope = iota
	// ScopeGuest is only available before login.
	ScopeGuest
	// ScopeAuthenticated requires a live session.
	ScopeAuthenticated
)

// Command is one entry of the interactive shell.
type Command interface {
	Name() string
	Aliases() []string
	Summary() string
	Usage() string
	Scope() Scope
	Execute(ctx context.Context, args []string) error
}

// baseCommand carries the metadata every command has, leaving the concrete
// types to implement Execute only.
type baseCommand struct {
	name    string
	aliases []string
	summary string
	usage   string
	scope   Scope
}

func (c baseCommand) Name() string      { return c.name }
func (c baseCommand) Aliases() []string { return c.aliases }
func (c baseCommand) Summary() string   { return c.summary }
func (c baseCommand) Usage() string     { return c.usage }
func (c baseCommand) Scope() Scope      { return c.scope }

// Registry maps names and aliases to commands and keeps the registration order
// for the help output.
type Registry struct {
	commands []Command
	index    map[string]Command
}

func NewRegistry() *Registry {
	return &Registry{index: make(map[string]Command)}
}

// Register adds commands. A duplicate name is a programming error, so it fails
// loudly at wiring time rather than misbehaving at runtime.
func (r *Registry) Register(commands ...Command) error {
	for _, command := range commands {
		for _, name := range append([]string{command.Name()}, command.Aliases()...) {
			if _, exists := r.index[name]; exists {
				return fmt.Errorf("command %q is already registered", name)
			}
			r.index[name] = command
		}
		r.commands = append(r.commands, command)
	}
	return nil
}

// Lookup resolves a name or alias.
func (r *Registry) Lookup(name string) (Command, bool) {
	command, ok := r.index[strings.ToLower(name)]
	return command, ok
}

// Available lists the commands that can be run in the current state.
func (r *Registry) Available(authenticated bool) []Command {
	out := make([]Command, 0, len(r.commands))
	for _, command := range r.commands {
		if inScope(command.Scope(), authenticated) {
			out = append(out, command)
		}
	}
	return out
}

// Names returns the primary names available in the current state, sorted so the
// completion list is stable.
func (r *Registry) Names(authenticated bool) []string {
	commands := r.Available(authenticated)
	names := make([]string, 0, len(commands))
	for _, command := range commands {
		names = append(names, command.Name())
	}
	sort.Strings(names)
	return names
}

// Suggest offers close matches for an unknown command.
func (r *Registry) Suggest(input string, authenticated bool) []string {
	input = strings.ToLower(input)
	var matches []string
	for _, name := range r.Names(authenticated) {
		if strings.HasPrefix(name, input) || editDistance(name, input) <= 2 {
			matches = append(matches, name)
		}
	}
	return matches
}

func inScope(scope Scope, authenticated bool) bool {
	switch scope {
	case ScopeGuest:
		return !authenticated
	case ScopeAuthenticated:
		return authenticated
	default:
		return true
	}
}

// editDistance is the usual Levenshtein distance, used only for "did you mean".
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		copy(prev, curr)
	}
	return prev[len(b)]
}
