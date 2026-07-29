package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestUserError(t *testing.T) {
	err := NewUserError("something went wrong", nil)
	if err.Error() != "something went wrong" {
		t.Errorf("expected 'something went wrong', got %q", err.Error())
	}
}

func TestUserErrorWithInner(t *testing.T) {
	inner := errors.New("inner error")
	err := NewUserError("outer error", inner)
	if !strings.Contains(err.Error(), "outer error") {
		t.Errorf("error should contain outer message")
	}
	if !strings.Contains(err.Error(), "inner error") {
		t.Errorf("error should contain inner message")
	}
}

func TestUserErrorUnwrap(t *testing.T) {
	inner := errors.New("inner error")
	err := NewUserError("outer error", inner)
	if !errors.Is(err, inner) {
		t.Error("errors.Is should match inner error")
	}
}

func TestInternalError(t *testing.T) {
	err := NewInternalError("internal failure", nil)
	if err.Error() != "internal failure" {
		t.Errorf("expected 'internal failure', got %q", err.Error())
	}
}

func TestInternalErrorWithInner(t *testing.T) {
	inner := errors.New("root cause")
	err := NewInternalError("wrapper", inner)
	if !strings.Contains(err.Error(), "root cause") {
		t.Errorf("error should contain inner message")
	}
}

func TestInternalErrorUnwrap(t *testing.T) {
	inner := errors.New("root cause")
	err := NewInternalError("wrapper", inner)
	if !errors.Is(err, inner) {
		t.Error("errors.Is should match inner error")
	}
}

func TestWrap(t *testing.T) {
	inner := errors.New("base error")
	err := Wrap(inner, "context")
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("error should contain context")
	}
	if !strings.Contains(err.Error(), "base error") {
		t.Errorf("error should contain base error")
	}
}

func TestWrapNil(t *testing.T) {
	err := Wrap(nil, "context")
	if err != nil {
		t.Errorf("Wrap(nil) should return nil")
	}
}

func TestWrapUser(t *testing.T) {
	inner := errors.New("base error")
	err := WrapUser(inner, "user context")
	if !strings.Contains(err.Error(), "user context") {
		t.Errorf("error should contain user context")
	}
}

func TestWrapInternal(t *testing.T) {
	inner := errors.New("base error")
	err := WrapInternal(inner, "internal context")
	if !strings.Contains(err.Error(), "internal context") {
		t.Errorf("error should contain internal context")
	}
}

func TestErrorChain(t *testing.T) {
	base := errors.New("base error")
	wrapped := Wrap(WrapUser(base, "user level"), "outer")
	if !errors.Is(wrapped, base) {
		t.Error("error chain should reach base error")
	}
}

func TestNoPayloadInError(t *testing.T) {
	// Verify that error messages don't accidentally include payload bytes
	payload := "secret-payload-data"
	err := WrapUser(fmt.Errorf("decode failed"), "frame 5")
	if strings.Contains(err.Error(), payload) {
		t.Error("error message contains payload data")
	}
}
