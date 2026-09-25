// Package clock hides time.Now behind an interface so that expiry and lockout
// logic can be tested without sleeping.
package clock

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// System returns a Clock backed by the wall clock, normalised to UTC so that
// values written to Postgres and printed in the CLI agree.
func System() Clock { return systemClock{} }

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Fake is a Clock the tests can move forward by hand.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

func NewFake(start time.Time) *Fake {
	return &Fake{now: start.UTC()}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
