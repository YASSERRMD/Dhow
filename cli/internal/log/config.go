// Package log provides a structured logger for Dhow.
//
// The logger is designed with the following principles:
// - Silent by default on the data path.
// - Structured (key-value pairs).
// - Levelled (debug, info, warn, error).
// - Never logs payload bytes or key material.
package log

import (
	"io"
	"os"
	"strings"
)

// Config holds logger configuration.
type Config struct {
	Level   string // "debug", "info", "warn", "error", "silent"
	Format  string // "text" or "json"
	Output  string // "stderr" or "stdout"
}

// DefaultConfig returns the default logger configuration.
func DefaultConfig() Config {
	return Config{
		Level:  "info",
		Format: "text",
		Output: "stderr",
	}
}

// ParseLevel parses a level string.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "silent", "off":
		return LevelDebug // handled by enabled=false
	default:
		return LevelInfo
	}
}

// NewFromConfig creates a Logger from a Config.
func NewFromConfig(cfg Config) *Logger {
	if cfg.Level == "silent" || cfg.Level == "off" {
		return NewSilent()
	}

	var w io.Writer
	switch cfg.Output {
	case "stdout":
		w = os.Stdout
	default:
		w = os.Stderr
	}

	return New(w, ParseLevel(cfg.Level))
}
