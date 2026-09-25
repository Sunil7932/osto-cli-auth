package cli

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ANSI escapes, emitted only when colour is enabled.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Printer writes user facing output. Keeping it separate from the commands
// means the wording and the colours are decided in one place.
type Printer struct {
	out   io.Writer
	color bool
}

func NewPrinter(out io.Writer, color bool) *Printer {
	return &Printer{out: out, color: color}
}

// Writer exposes the underlying stream for output that is not line based, such
// as the QR code drawn during 2FA setup.
func (p *Printer) Writer() io.Writer { return p.out }

func (p *Printer) paint(code, text string) string {
	if !p.color {
		return text
	}
	return code + text + ansiReset
}

func (p *Printer) Printf(format string, args ...any) {
	fmt.Fprintf(p.out, format, args...)
}

func (p *Printer) Println(args ...any) {
	fmt.Fprintln(p.out, args...)
}

func (p *Printer) Success(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n", p.paint(ansiGreen, "✓"), fmt.Sprintf(format, args...))
}

func (p *Printer) Failure(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n", p.paint(ansiRed, "✗"), fmt.Sprintf(format, args...))
}

func (p *Printer) Warn(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n", p.paint(ansiYellow, "!"), fmt.Sprintf(format, args...))
}

func (p *Printer) Info(format string, args ...any) {
	fmt.Fprintf(p.out, "%s\n", fmt.Sprintf(format, args...))
}

func (p *Printer) Hint(format string, args ...any) {
	fmt.Fprintf(p.out, "%s\n", p.paint(ansiDim, "  "+fmt.Sprintf(format, args...)))
}

func (p *Printer) Heading(text string) {
	fmt.Fprintf(p.out, "\n%s\n", p.paint(ansiBold, text))
}

// KeyValues prints an aligned two column block, used for account details and
// the help listing.
func (p *Printer) KeyValues(rows [][2]string) {
	width := 0
	for _, row := range rows {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}
	for _, row := range rows {
		label := row[0] + strings.Repeat(" ", width-len(row[0]))
		fmt.Fprintf(p.out, "  %s  %s\n", p.paint(ansiCyan, label), row[1])
	}
}

// formatTime renders a timestamp in local time, or a dash when absent.
func formatTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

// formatDuration prints durations the way a person would read them out.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	d = d.Round(time.Second)

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	switch {
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
