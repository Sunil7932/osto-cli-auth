package cli

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type fakeCommand struct {
	baseCommand
	calls int
}

func (c *fakeCommand) Execute(context.Context, []string) error {
	c.calls++
	return nil
}

func newFakeCommand(name string, scope Scope, aliases ...string) *fakeCommand {
	return &fakeCommand{baseCommand: baseCommand{
		name:    name,
		aliases: aliases,
		summary: name + " summary",
		usage:   name,
		scope:   scope,
	}}
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()

	registry := NewRegistry()
	err := registry.Register(
		newFakeCommand("register", ScopeGuest),
		newFakeCommand("login", ScopeGuest),
		newFakeCommand("whoami", ScopeAuthenticated, "me"),
		newFakeCommand("logout", ScopeAuthenticated),
		newFakeCommand("help", ScopeAlways, "?"),
		newFakeCommand("exit", ScopeAlways, "quit"),
	)
	if err != nil {
		t.Fatalf("register commands: %v", err)
	}
	return registry
}

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	registry := NewRegistry()

	if err := registry.Register(newFakeCommand("login", ScopeGuest)); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := registry.Register(newFakeCommand("login", ScopeGuest)); err == nil {
		t.Fatal("expected the duplicate name to be rejected")
	}
	// An alias clashing with an existing name is just as bad.
	if err := registry.Register(newFakeCommand("signin", ScopeGuest, "login")); err == nil {
		t.Fatal("expected the duplicate alias to be rejected")
	}
}

func TestRegistryLookupHandlesAliasesAndCase(t *testing.T) {
	registry := testRegistry(t)

	for _, name := range []string{"whoami", "me", "WhoAmI"} {
		command, ok := registry.Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q) failed", name)
		}
		if command.Name() != "whoami" {
			t.Errorf("Lookup(%q) = %q, want whoami", name, command.Name())
		}
	}

	if _, ok := registry.Lookup("nope"); ok {
		t.Error("an unknown command should not resolve")
	}
}

func TestRegistryVisibilityFollowsLoginState(t *testing.T) {
	registry := testRegistry(t)

	guest := registry.Names(false)
	want := []string{"exit", "help", "login", "register"}
	if !slices.Equal(guest, want) {
		t.Errorf("guest commands = %v, want %v", guest, want)
	}

	signedIn := registry.Names(true)
	want = []string{"exit", "help", "logout", "whoami"}
	if !slices.Equal(signedIn, want) {
		t.Errorf("signed in commands = %v, want %v", signedIn, want)
	}
}

func TestRegistrySuggestsCloseMatches(t *testing.T) {
	registry := testRegistry(t)

	if got := registry.Suggest("logi", false); !slices.Contains(got, "login") {
		t.Errorf("Suggest(\"logi\") = %v, want it to contain login", got)
	}
	if got := registry.Suggest("registr", false); !slices.Contains(got, "register") {
		t.Errorf("Suggest(\"registr\") = %v, want it to contain register", got)
	}
	if got := registry.Suggest("whoami", false); len(got) != 0 {
		t.Errorf("Suggest(\"whoami\") = %v, want nothing while logged out", got)
	}
}

func TestCompleterCompletesCommandNames(t *testing.T) {
	registry := testRegistry(t)
	state := NewState()
	completer := NewCompleter(registry, state)

	candidates, length := completer.Do([]rune("lo"), 2)
	if length != 2 {
		t.Errorf("consumed length = %d, want 2", length)
	}
	if got := asStrings(candidates); !slices.Equal(got, []string{"gin"}) {
		t.Errorf("candidates = %v, want [gin]", got)
	}

	// With nothing typed everything in scope is offered.
	candidates, _ = completer.Do(nil, 0)
	if len(candidates) != len(registry.Names(false)) {
		t.Errorf("got %d candidates, want %d", len(candidates), len(registry.Names(false)))
	}

	// The argument of help completes to command names as well.
	candidates, length = completer.Do([]rune("help lo"), 7)
	if length != 2 {
		t.Errorf("consumed length = %d, want 2", length)
	}
	if got := asStrings(candidates); !slices.Equal(got, []string{"gin"}) {
		t.Errorf("candidates = %v, want [gin]", got)
	}

	// Other commands take no arguments, so nothing is suggested.
	if candidates, _ = completer.Do([]rune("login al"), 8); len(candidates) != 0 {
		t.Errorf("candidates = %v, want none", asStrings(candidates))
	}
}

func TestStateTracksTheCurrentLogin(t *testing.T) {
	state := NewState()

	if state.IsAuthenticated() || state.Username() != "guest" {
		t.Fatalf("a fresh state should be a guest, got %q", state.Username())
	}

	state.Set("token", nil, &testUser)
	if !state.IsAuthenticated() || state.Username() != "alice" {
		t.Fatalf("state = %+v, want alice signed in", state)
	}

	state.Clear()
	if state.IsAuthenticated() || state.Token() != "" {
		t.Fatal("clearing the state must drop the token")
	}
}

func TestSentenceTidiesValidationMessages(t *testing.T) {
	cases := map[string]string{
		"password must be longer": "Password must be longer.",
		"already a sentence.":     "Already a sentence.",
		"":                        "",
	}
	for input, want := range cases {
		if got := sentence(input); got != want {
			t.Errorf("sentence(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEditDistanceIsSymmetric(t *testing.T) {
	if got := editDistance("login", "logni"); got != 2 {
		t.Errorf("editDistance(login, logni) = %d, want 2", got)
	}
	if editDistance("login", "logni") != editDistance("logni", "login") {
		t.Error("edit distance should be symmetric")
	}
}

func TestParsePositiveIntRejectsGarbage(t *testing.T) {
	if _, err := parsePositiveInt("12a"); err == nil {
		t.Error("expected a non numeric value to be rejected")
	}
	if _, err := parsePositiveInt("0"); err == nil {
		t.Error("expected zero to be rejected")
	}
	value, err := parsePositiveInt("25")
	if err != nil || value != 25 {
		t.Errorf("parsePositiveInt(\"25\") = %d, %v, want 25 and nil", value, err)
	}
}

func TestAbortedErrorIsRecognisable(t *testing.T) {
	if !errors.Is(ErrAborted, ErrAborted) {
		t.Fatal("ErrAborted should match itself")
	}
}

func asStrings(runes [][]rune) []string {
	out := make([]string, 0, len(runes))
	for _, candidate := range runes {
		out = append(out, string(candidate))
	}
	return out
}
