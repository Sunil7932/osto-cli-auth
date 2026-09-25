package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"golang.org/x/term"
)

// ErrAborted is returned when the user presses Ctrl-C at a prompt. Commands
// treat it as "cancel this operation", not as a failure.
var ErrAborted = errors.New("aborted by user")

// Prompter reads input from the user. Two implementations exist: a readline
// backed one with history and completion for real terminals, and a line reader
// used when stdin is a pipe (CI, `echo ... | authcli`).
type Prompter interface {
	ReadLine(prompt string) (string, error)
	ReadSecret(prompt string) (string, error)
	Interactive() bool
	Close() error
}

// PrompterOptions configures the interactive prompter.
type PrompterOptions struct {
	HistoryFile  string
	HistoryLimit int
	Completer    readline.AutoCompleter
	Output       io.Writer
}

// NewPrompter returns the interactive prompter when stdin is a terminal and
// falls back to the plain reader otherwise.
func NewPrompter(opts PrompterOptions) (Prompter, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return newPipePrompter(os.Stdin, opts.Output), nil
	}

	instance, err := readline.NewEx(&readline.Config{
		HistoryFile:            opts.HistoryFile,
		HistoryLimit:           opts.HistoryLimit,
		AutoComplete:           opts.Completer,
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		HistorySearchFold:      true,
		DisableAutoSaveHistory: false,
		Stdout:                 opts.Output,
	})
	if err != nil {
		return nil, fmt.Errorf("start interactive prompt: %w", err)
	}
	return &readlinePrompter{instance: instance}, nil
}

type readlinePrompter struct {
	instance *readline.Instance
}

func (p *readlinePrompter) ReadLine(prompt string) (string, error) {
	p.instance.SetPrompt(prompt)
	line, err := p.instance.Readline()
	if err != nil {
		return "", translateReadlineError(err)
	}
	return strings.TrimSpace(line), nil
}

func (p *readlinePrompter) ReadSecret(prompt string) (string, error) {
	raw, err := p.instance.ReadPassword(prompt)
	if err != nil {
		return "", translateReadlineError(err)
	}
	return string(raw), nil
}

func (p *readlinePrompter) Interactive() bool { return true }

func (p *readlinePrompter) Close() error { return p.instance.Close() }

// translateReadlineError maps the library sentinels onto ours so the rest of
// the package does not import readline.
func translateReadlineError(err error) error {
	switch {
	case errors.Is(err, readline.ErrInterrupt):
		return ErrAborted
	case errors.Is(err, io.EOF):
		return io.EOF
	default:
		return err
	}
}

// pipePrompter keeps the CLI scriptable. History and completion are terminal
// features, so they are simply absent here.
type pipePrompter struct {
	reader *bufio.Reader
	input  *os.File
	out    io.Writer
}

func newPipePrompter(input *os.File, out io.Writer) *pipePrompter {
	if out == nil {
		out = os.Stdout
	}
	return &pipePrompter{reader: bufio.NewReader(input), input: input, out: out}
}

func (p *pipePrompter) ReadLine(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	line, err := p.reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
			// Last line of a pipe without a trailing newline.
			fmt.Fprintln(p.out, strings.TrimSpace(line))
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	line = strings.TrimSpace(line)
	// Echo the input so a transcript of a piped run still reads correctly.
	fmt.Fprintln(p.out, line)
	return line, nil
}

func (p *pipePrompter) ReadSecret(prompt string) (string, error) {
	if term.IsTerminal(int(p.input.Fd())) {
		fmt.Fprint(p.out, prompt)
		raw, err := term.ReadPassword(int(p.input.Fd()))
		fmt.Fprintln(p.out)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}

	fmt.Fprint(p.out, prompt)
	line, err := p.reader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	fmt.Fprintln(p.out)
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *pipePrompter) Interactive() bool { return false }

func (p *pipePrompter) Close() error { return nil }

// commandCompleter completes command names, and the argument of `help`, based on
// what is currently in scope.
type commandCompleter struct {
	names func() []string
}

func (c *commandCompleter) Do(line []rune, pos int) ([][]rune, int) {
	typed := string(line[:pos])
	fields := strings.Fields(typed)

	// Completing the first word, unless it is already finished by a space.
	if len(fields) == 0 || (len(fields) == 1 && !strings.HasSuffix(typed, " ")) {
		prefix := ""
		if len(fields) == 1 {
			prefix = fields[0]
		}
		return suffixes(c.names(), prefix), len([]rune(prefix))
	}

	if fields[0] != "help" {
		return nil, 0
	}

	prefix := ""
	if len(fields) > 1 && !strings.HasSuffix(typed, " ") {
		prefix = fields[len(fields)-1]
	}
	return suffixes(c.names(), prefix), len([]rune(prefix))
}

func suffixes(candidates []string, prefix string) [][]rune {
	var out [][]rune
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, prefix) {
			out = append(out, []rune(candidate[len(prefix):]))
		}
	}
	return out
}
