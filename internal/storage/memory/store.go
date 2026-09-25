// Package memory provides an in-memory implementation of the domain ports.
//
// It exists for the unit tests: the auth service can be exercised end to end,
// including lockouts and session expiry, without a database container. Keeping
// a second adapter around is also the cheapest way to prove the ports are not
// leaking Postgres specifics.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// Store holds all three repositories so tests can share one fixture.
type Store struct {
	mu sync.RWMutex

	users    map[int64]domain.User
	sessions map[int64]domain.Session
	events   []domain.AuthEvent

	nextUserID    int64
	nextSessionID int64
	nextEventID   int64
}

func NewStore() *Store {
	return &Store{
		users:         make(map[int64]domain.User),
		sessions:      make(map[int64]domain.Session),
		nextUserID:    1,
		nextSessionID: 1,
		nextEventID:   1,
	}
}

func (s *Store) Users() domain.UserRepository       { return (*userRepository)(s) }
func (s *Store) Sessions() domain.SessionRepository { return (*sessionRepository)(s) }
func (s *Store) Events() domain.EventRepository     { return (*eventRepository)(s) }

// TxManager satisfies the unit of work port. There is nothing to commit here,
// so it just runs the function.
func (s *Store) TxManager() domain.TxManager { return txManager{} }

type txManager struct{}

func (txManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type userRepository Store

func (r *userRepository) store() *Store { return (*Store)(r) }

func (r *userRepository) Create(_ context.Context, user *domain.User) (*domain.User, error) {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.users {
		if existing.Username == user.Username {
			return nil, domain.ErrUsernameTaken
		}
	}

	stored := *user
	stored.ID = s.nextUserID
	s.nextUserID++
	s.users[stored.ID] = stored

	clone := stored
	return &clone, nil
}

func (r *userRepository) FindByID(_ context.Context, id int64) (*domain.User, error) {
	s := r.store()
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	clone := user
	return &clone, nil
}

func (r *userRepository) FindByUsername(_ context.Context, username string) (*domain.User, error) {
	s := r.store()
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			clone := user
			return &clone, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *userRepository) Update(_ context.Context, user *domain.User) error {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[user.ID]; !ok {
		return domain.ErrNotFound
	}
	s.users[user.ID] = *user
	return nil
}

type sessionRepository Store

func (r *sessionRepository) store() *Store { return (*Store)(r) }

func (r *sessionRepository) Create(_ context.Context, session *domain.Session) (*domain.Session, error) {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := *session
	stored.ID = s.nextSessionID
	s.nextSessionID++
	s.sessions[stored.ID] = stored

	clone := stored
	return &clone, nil
}

func (r *sessionRepository) FindByTokenHash(_ context.Context, tokenHash string) (*domain.Session, error) {
	s := r.store()
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, session := range s.sessions {
		if session.TokenHash == tokenHash {
			clone := session
			return &clone, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *sessionRepository) Touch(_ context.Context, id int64, lastSeenAt, idleExpiresAt time.Time) error {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok || session.RevokedAt != nil {
		return domain.ErrNotFound
	}
	session.LastSeenAt = lastSeenAt
	session.IdleExpiresAt = idleExpiresAt
	s.sessions[id] = session
	return nil
}

func (r *sessionRepository) Revoke(_ context.Context, id int64, revokedAt time.Time) error {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return domain.ErrNotFound
	}
	if session.RevokedAt == nil {
		session.RevokedAt = &revokedAt
		s.sessions[id] = session
	}
	return nil
}

func (r *sessionRepository) RevokeAllForUser(_ context.Context, userID int64, revokedAt time.Time) (int64, error) {
	return r.revokeMatching(userID, 0, revokedAt)
}

func (r *sessionRepository) RevokeAllForUserExcept(_ context.Context, userID, exceptID int64, revokedAt time.Time) (int64, error) {
	return r.revokeMatching(userID, exceptID, revokedAt)
}

func (r *sessionRepository) revokeMatching(userID, exceptID int64, revokedAt time.Time) (int64, error) {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	var revoked int64
	for id, session := range s.sessions {
		if session.UserID != userID || session.RevokedAt != nil {
			continue
		}
		if exceptID != 0 && id == exceptID {
			continue
		}
		session.RevokedAt = &revokedAt
		s.sessions[id] = session
		revoked++
	}
	return revoked, nil
}

func (r *sessionRepository) DeleteExpired(_ context.Context, olderThan time.Time) (int64, error) {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int64
	for id, session := range s.sessions {
		if !session.IsActive(olderThan) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

type eventRepository Store

func (r *eventRepository) store() *Store { return (*Store)(r) }

func (r *eventRepository) Append(_ context.Context, event domain.AuthEvent) error {
	s := r.store()
	s.mu.Lock()
	defer s.mu.Unlock()

	event.ID = s.nextEventID
	s.nextEventID++
	s.events = append(s.events, event)
	return nil
}

func (r *eventRepository) RecentForUser(_ context.Context, userID int64, limit int) ([]domain.AuthEvent, error) {
	s := r.store()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []domain.AuthEvent
	for _, event := range s.events {
		if event.UserID != nil && *event.UserID == userID {
			matches = append(matches, event)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].CreatedAt.Equal(matches[j].CreatedAt) {
			return matches[i].ID > matches[j].ID
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches, nil
}

// AllEvents returns every recorded event, which is handy in assertions.
func (s *Store) AllEvents() []domain.AuthEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]domain.AuthEvent, len(s.events))
	copy(out, s.events)
	return out
}
