package domain

import "time"

// EventType enumerates the security relevant things that can happen to an
// account. They are appended to auth_events so a failed login can still be
// traced after the counters on the user row have been reset.
type EventType string

const (
	EventRegistered     EventType = "registered"
	EventLoginSucceeded EventType = "login_succeeded"
	EventLoginFailed    EventType = "login_failed"
	EventTOTPChallenged EventType = "totp_challenged"
	EventTOTPFailed     EventType = "totp_failed"
	EventAccountLocked  EventType = "account_locked"
	EventLogout         EventType = "logout"
	EventSessionExpired EventType = "session_expired"
	EventTOTPEnabled    EventType = "totp_enabled"
	EventTOTPDisabled   EventType = "totp_disabled"
)

// AuthEvent is an append-only audit record.
type AuthEvent struct {
	ID int64
	// UserID is nil when the attempt referenced an account that does not exist.
	UserID    *int64
	Username  string
	Type      EventType
	Detail    string
	CreatedAt time.Time
}
