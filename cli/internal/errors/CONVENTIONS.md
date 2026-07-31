# Dhow CLI Error Wrapping Conventions

## Overview

All errors in the Dhow CLI follow a consistent wrapping convention to ensure
that:

1. Errors are always wrapped with context.
2. Foreign errors are never returned naked.
3. Error messages never contain payload bytes or key material.
4. Errors are classified into user-facing and internal categories.

## Error Types

### `UserError`

A `UserError` is safe to show to the end user. It contains a human-readable
message and optionally wraps an underlying error.

```go
err := errors.NewUserError("failed to read config file", err)
```

### `InternalError`

An `InternalError` represents an internal failure that should not expose
implementation details. The message is generic; the underlying error is
preserved for debugging.

```go
err := errors.NewInternalError("unexpected state in decoder", err)
```

## Wrapping Functions

### `Wrap(err, message)`

Wraps an error with context using `fmt.Errorf`.

```go
return errors.Wrap(err, "failed to open key file")
```

### `WrapUser(err, message)`

Wraps an error as a `UserError`.

```go
return errors.WrapUser(err, "invalid configuration")
```

### `WrapInternal(err, message)`

Wraps an error as an `InternalError`.

```go
return errors.WrapInternal(err, "decoder state machine failure")
```

## Rules

1. **Never return a naked foreign error.** Always wrap with context.
2. **Never include payload bytes in error messages.** Error messages must
   not contain ciphertext, plaintext, or key material.
3. **Classify errors.** Use `UserError` for user-facing issues and
   `InternalError` for internal failures.
4. **Preserve the error chain.** Use `%w` for wrapping so `errors.Is` and
   `errors.As` work correctly.
5. **Be specific.** Error messages should explain what failed and, if possible,
   what to do about it.

## Examples

### Good

```go
return errors.WrapUser(err, "failed to read manifest: check file permissions")
```

### Bad

```go
return err // naked foreign error
```

### Bad

```go
return fmt.Errorf("failed to decrypt: %s", string(ciphertext)) // leaks payload
```
