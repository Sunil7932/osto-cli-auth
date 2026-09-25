package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/Sunil7932/cli-login-2fa/internal/clock"
	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// Challenge is the state between "password accepted" and "code accepted". It
// exists so the password does not have to be sent a second time along with the
// one time code.
type Challenge struct {
	ID        string
	UserID    int64
	Username  string
	Attempts  int
	ExpiresAt time.Time
}

// ChallengeStore keeps pending two factor challenges. The CLI is a single
// process, so an in-memory store is enough; a server deployment would swap in
// a Redis or Postgres backed implementation without touching the service.
type ChallengeStore interface {
	Save(ctx context.Context, challenge Challenge) error
	Find(ctx context.Context, id string) (Challenge, error)
	Delete(ctx context.Context, id string) error
}

// MemoryChallengeStore is a concurrency safe map with lazy expiry.
type MemoryChallengeStore struct {
	mu    sync.Mutex
	clock clock.Clock
	items map[string]Challenge
}

func NewMemoryChallengeStore(clk clock.Clock) *MemoryChallengeStore {
	return &MemoryChallengeStore{
		clock: clk,
		items: make(map[string]Challenge),
	}
}

func (s *MemoryChallengeStore) Save(_ context.Context, challenge Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	s.items[challenge.ID] = challenge
	return nil
}

func (s *MemoryChallengeStore) Find(_ context.Context, id string) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, ok := s.items[id]
	if !ok {
		return Challenge{}, domain.ErrNotFound
	}
	if !challenge.ExpiresAt.After(s.clock.Now()) {
		delete(s.items, id)
		return Challenge{}, domain.ErrNotFound
	}
	return challenge, nil
}

func (s *MemoryChallengeStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	return nil
}

func (s *MemoryChallengeStore) evictExpiredLocked() {
	now := s.clock.Now()
	for id, challenge := range s.items {
		if !challenge.ExpiresAt.After(now) {
			delete(s.items, id)
		}
	}
}

func newChallengeID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate challenge id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
