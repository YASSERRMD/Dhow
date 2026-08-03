// Package log provides a structured logger for Dhow.
//
// The logger is designed with the following principles:
// - Silent by default on the data path.
// - Structured (key-value pairs).
// - Levelled (debug, info, warn, error).
// - Never logs payload bytes or key material.
package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents the log level.
type Level int

const (
	// LevelDebug is the debug log level.
	LevelDebug Level = iota
	// LevelInfo is the info log level.
	LevelInfo
	// LevelWarn is the warn log level.
	LevelWarn
	// LevelError is the error log level.
	LevelError
)

var levelNames = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
}

// Logger is a structured logger.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	level   Level
	enabled bool
}

// New creates a new Logger.
func New(w io.Writer, level Level) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{
		w:       w,
		level:   level,
		enabled: true,
	}
}

// NewDefault creates a new Logger writing to stderr at Info level.
func NewDefault() *Logger {
	return New(os.Stderr, LevelInfo)
}

// NewSilent creates a new Logger that discards all output.
func NewSilent() *Logger {
	return &Logger{
		w:       io.Discard,
		level:   LevelDebug,
		enabled: false,
	}
}

// SetLevel sets the log level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetEnabled enables or disables logging.
func (l *Logger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// Enabled returns whether logging is enabled.
func (l *Logger) Enabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled
}

// Debug logs a debug-level message.
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs an info-level message.
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs a warn-level message.
func (l *Logger) Warn(msg string, fields ...Field) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs an error-level message.
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(LevelError, msg, fields...)
}

func (l *Logger) log(level Level, msg string, fields ...Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.enabled || level < l.level {
		return
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	levelStr := levelNames[level]

	line := fmt.Sprintf("%s %s %s", ts, levelStr, msg)
	for _, f := range fields {
		line += fmt.Sprintf(" %s=%v", f.Key, f.Value)
	}
	line += "\n"

	_, _ = l.w.Write([]byte(line))
}

// Field represents a key-value field in a log entry.
type Field struct {
	Key   string
	Value any
}

// String creates a string field.
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field.
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Int64 creates an int64 field.
func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a boolean field.
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Error creates an error field.
func Error(key string, err error) Field {
	return Field{Key: key, Value: err.Error()}
}

// Duration creates a duration field.
func Duration(key string, d time.Duration) Field {
	return Field{Key: key, Value: d.String()}
}
