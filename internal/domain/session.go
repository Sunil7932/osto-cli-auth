package domain

import "time"

// Session is a login that survives in the database. Only the SHA-256 hash of
// the token is stored, the plaintext token never leaves the client process.
//
// Two deadlines are tracked on purpose:
//
//	IdleExpiresAt     moves forward on every authenticated command
//	AbsoluteExpiresAt is fixed at login and caps how long a session may live
type Session struct {
	ID                int64
	UserID            int64
	TokenHash         string
	IssuedAt          time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	ClientInfo        string
}

// ExpiresAt is the effective deadline, whichever limit bites first.
func (s *Session) ExpiresAt() time.Time {
	if s.IdleExpiresAt.Before(s.AbsoluteExpiresAt) {
		return s.IdleExpiresAt
	}
	return s.AbsoluteExpiresAt
}

// IsActive reports whether the session may still be used at now.
func (s *Session) IsActive(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return s.ExpiresAt().After(now)
}

// TimeLeft is the remaining validity, never negative.
func (s *Session) TimeLeft(now time.Time) time.Duration {
	left := s.ExpiresAt().Sub(now)
	if left < 0 {
		return 0
	}
	return left
}
