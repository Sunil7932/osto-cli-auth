package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

var testUser = domain.User{
	ID:        1,
	Username:  "alice",
	CreatedAt: time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC),
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0:                           "expired",
		-time.Minute:                "expired",
		45 * time.Second:            "45s",
		90 * time.Second:            "1m 30s",
		2*time.Hour + 5*time.Minute: "2h 5m",
	}
	for input, want := range cases {
		if got := formatDuration(input); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatTimeHandlesMissingValues(t *testing.T) {
	if got := formatTime(nil); got != "-" {
		t.Errorf("formatTime(nil) = %q, want -", got)
	}

	var zero time.Time
	if got := formatTime(&zero); got != "-" {
		t.Errorf("formatTime(zero) = %q, want -", got)
	}

	moment := time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC)
	if got := formatTime(&moment); !strings.HasPrefix(got, "2026-02-14") {
		t.Errorf("formatTime(%v) = %q, want it to start with the date", moment, got)
	}
}

func TestDescribeMFA(t *testing.T) {
	confirmed := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		user domain.User
		want string
	}{
		{"off", domain.User{}, "disabled"},
		{"pending", domain.User{TOTPSecret: "cipher-text"}, "disabled (setup started but never confirmed)"},
		{"on", domain.User{TOTPEnabled: true, TOTPSecret: "cipher-text", TOTPConfirmedAt: &confirmed}, "enabled (since"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeMFA(&tc.user)
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("describeMFA() = %q, want it to start with %q", got, tc.want)
			}
		})
	}
}

// The assignment asks for a specific set of details right after login, so the
// summary block is worth pinning down.
func TestRenderAccountShowsTheRequiredDetails(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(&buf, false)

	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	lastLogin := now.Add(-24 * time.Hour)
	session := &domain.Session{
		UserID:            testUser.ID,
		IssuedAt:          now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}

	renderAccount(printer, accountView{
		user:      &testUser,
		session:   session,
		lastLogin: &lastLogin,
		now:       now,
	})

	output := buf.String()
	for _, want := range []string{
		"Username", "alice",
		"Registered", "2026-02-14",
		"Two factor", "disabled",
		"Session expires", "in 15m 0s",
		"Last login",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("summary is missing %q:\n%s", want, output)
		}
	}
}

func TestPrinterOmitsColourWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	NewPrinter(&buf, false).Success("done")

	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("expected plain output, got %q", buf.String())
	}

	buf.Reset()
	NewPrinter(&buf, true).Success("done")
	if !strings.Contains(buf.String(), "\033[") {
		t.Errorf("expected coloured output, got %q", buf.String())
	}
}
