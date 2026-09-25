package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Enrollment is what the user needs in order to add the account to their
// authenticator app.
type Enrollment struct {
	Secret string
	// URI is the otpauth:// provisioning URI, which is also what the QR code
	// printed by the CLI encodes.
	URI string
}

// TOTPProvider issues and verifies RFC 6238 one time passwords.
type TOTPProvider interface {
	Enroll(accountName string) (Enrollment, error)
	Verify(secret, code string, now time.Time) bool
}

// GoogleAuthenticator produces SHA-1, 6 digit, 30 second codes, which is the
// combination every mainstream authenticator app supports.
type GoogleAuthenticator struct {
	issuer string
	period uint
	skew   uint
	digits otp.Digits
}

func NewGoogleAuthenticator(issuer string, skewPeriods uint) *GoogleAuthenticator {
	return &GoogleAuthenticator{
		issuer: issuer,
		period: 30,
		skew:   skewPeriods,
		digits: otp.DigitsSix,
	}
}

func (g *GoogleAuthenticator) Enroll(accountName string) (Enrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      g.issuer,
		AccountName: accountName,
		Period:      g.period,
		SecretSize:  20,
		Digits:      g.digits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return Enrollment{}, fmt.Errorf("generate totp secret: %w", err)
	}
	return Enrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

func (g *GoogleAuthenticator) Verify(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if secret == "" || code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period:    g.period,
		Skew:      g.skew,
		Digits:    g.digits,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}
