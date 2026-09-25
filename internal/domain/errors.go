package domain

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound is returned by repositories when a lookup matches nothing.
	ErrNotFound = errors.New("not found")
	// ErrUsernameTaken maps the unique constraint on users.username to a
	// domain level error so callers do not have to inspect driver errors.
	ErrUsernameTaken = errors.New("username already taken")
)

// ValidationError describes input the user can fix themselves.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s %s", e.Field, e.Message)
}

// IsValidation reports whether err was caused by bad user input.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}
