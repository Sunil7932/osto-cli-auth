package cli

import "github.com/Sunil7932/cli-login-2fa/internal/domain"

// State is the client side view of the current login. The session token lives
// here and nowhere else: it is never written to disk, so closing the CLI always
// leaves an attacker with nothing to replay.
//
// The shell is single threaded, so no locking is needed.
type State struct {
	token   string
	session *domain.Session
	user    *domain.User
}

func NewState() *State { return &State{} }

func (s *State) IsAuthenticated() bool { return s.token != "" && s.user != nil }

func (s *State) Token() string { return s.token }

func (s *State) User() *domain.User { return s.user }

func (s *State) Session() *domain.Session { return s.session }

func (s *State) Set(token string, session *domain.Session, user *domain.User) {
	s.token = token
	s.session = session
	s.user = user
}

// Refresh updates the cached session and user after a successful revalidation.
func (s *State) Refresh(session *domain.Session, user *domain.User) {
	s.session = session
	s.user = user
}

func (s *State) Clear() {
	s.token = ""
	s.session = nil
	s.user = nil
}

// Username is the name shown in the prompt, or "guest".
func (s *State) Username() string {
	if s.user == nil {
		return "guest"
	}
	return s.user.Username
}
