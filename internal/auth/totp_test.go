package auth_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Sunil7932/cli-login-2fa/internal/auth"
)

func TestGoogleAuthenticatorProducesAScannableEnrollment(t *testing.T) {
	provider := auth.NewGoogleAuthenticator("osto-cli-auth", 1)

	enrollment, err := provider.Enroll("alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	uri, err := url.Parse(enrollment.URI)
	if err != nil {
		t.Fatalf("parse provisioning uri: %v", err)
	}
	if uri.Scheme != "otpauth" || uri.Host != "totp" {
		t.Errorf("uri = %q, want an otpauth://totp/ URI", enrollment.URI)
	}
	if got := uri.Query().Get("issuer"); got != "osto-cli-auth" {
		t.Errorf("issuer = %q, want osto-cli-auth", got)
	}
	if got := uri.Query().Get("secret"); got != enrollment.Secret {
		t.Errorf("secret in uri = %q, want %q", got, enrollment.Secret)
	}
	if uri.Path != "/osto-cli-auth:alice" {
		t.Errorf("label = %q, want /osto-cli-auth:alice", uri.Path)
	}
}

func TestGoogleAuthenticatorVerifiesCurrentCodes(t *testing.T) {
	provider := auth.NewGoogleAuthenticator("osto-cli-auth", 1)
	enrollment, err := provider.Enroll("alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	code, err := totp.GenerateCode(enrollment.Secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if !provider.Verify(enrollment.Secret, code, now) {
		t.Error("the current code should be accepted")
	}
	if !provider.Verify(enrollment.Secret, " "+code+" ", now) {
		t.Error("surrounding whitespace should be tolerated")
	}
	if provider.Verify(enrollment.Secret, code, now.Add(10*time.Minute)) {
		t.Error("a code from ten minutes ago must not be accepted")
	}
	if provider.Verify("", code, now) || provider.Verify(enrollment.Secret, "", now) {
		t.Error("empty input must never verify")
	}
}

// A skew of one period covers a device whose clock is half a minute off.
func TestGoogleAuthenticatorToleratesConfiguredSkew(t *testing.T) {
	now := time.Date(2026, 3, 1, 9, 0, 45, 0, time.UTC)
	previousPeriod := now.Add(-30 * time.Second)

	lenient := auth.NewGoogleAuthenticator("osto-cli-auth", 1)
	enrollment, err := lenient.Enroll("alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, previousPeriod)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if !lenient.Verify(enrollment.Secret, code, now) {
		t.Error("with a skew of one period the previous code should still work")
	}

	strict := auth.NewGoogleAuthenticator("osto-cli-auth", 0)
	if strict.Verify(enrollment.Secret, code, now) {
		t.Error("with no skew the previous code must be refused")
	}
}
