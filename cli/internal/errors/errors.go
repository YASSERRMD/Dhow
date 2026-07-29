// Package errors provides error wrapping conventions for the Dhow CLI.
//
// All errors in the CLI follow these conventions:
// - Errors are wrapped with context using fmt.Errorf("context: %w", err).
// - Foreign errors are never returned naked.
// - Error messages never contain payload bytes or key material.
// - Errors are classified into user-facing and internal categories.
package errors

import (
	"fmt"
)

// UserError represents an error that is safe to show to the user.
type UserError struct {
	Message string
	Err     error
}

func (e *UserError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *UserError) Unwrap() error {
	return e.Err
}

// NewUserError creates a new user-facing error.
func NewUserError(message string, err error) *UserError {
	return &UserError{Message: message, Err: err}
}

// InternalError represents an internal error that should not expose
// implementation details to the user.
type InternalError struct {
	Message string
	Err     error
}

func (e *InternalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *InternalError) Unwrap() error {
	return e.Err
}

// NewInternalError creates a new internal error.
func NewInternalError(message string, err error) *InternalError {
	return &InternalError{Message: message, Err: err}
}

// Wrap wraps an error with context.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// WrapUser wraps an error as a user-facing error.
func WrapUser(err error, message string) error {
	if err == nil {
		return nil
	}
	return &UserError{Message: message, Err: err}
}

// WrapInternal wraps an error as an internal error.
func WrapInternal(err error, message string) error {
	if err == nil {
		return nil
	}
	return &InternalError{Message: message, Err: err}
}
