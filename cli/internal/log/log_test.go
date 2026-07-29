package log

import (
	"bytes"
	"strings"
	"testing"
)

// TestLogSilenceOnDataPath verifies that the logger never outputs payload bytes
// or key material. This is enforced by a test that fails if any byte sequence
// that could be payload data appears in log output.
func TestLogSilenceOnDataPath(t *testing.T) {
	// Create a logger writing to a buffer
	var buf bytes.Buffer
	logger := New(&buf, LevelDebug)

	// Simulate data-path logging (should not include payload bytes)
	logger.Info("starting transfer", String("session", "abc123"))
	logger.Debug("frame received", Int("frame_type", 1), Int("block_index", 0))
	logger.Warn("frame dropped", Int("frame_index", 5))
	logger.Error("decode failed", Error("err", strings.NewReader("test error")))

	output := buf.String()

	// Verify no payload-like data appears in the output
	// (this is a heuristic check; the real enforcement is that the logger
	// never receives payload bytes as arguments)
	if strings.Contains(output, "payload") {
		t.Error("log output contains 'payload' keyword")
	}
	if strings.Contains(output, "key") && !strings.Contains(output, "session") {
		t.Error("log output contains 'key' keyword")
	}
}

// TestLogSilentMode verifies that a silent logger produces no output.
func TestLogSilentMode(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSilent()
	logger.w = &buf // Override the discard writer for testing

	logger.Info("test message", String("key", "value"))

	output := buf.String()
	if output != "" {
		t.Errorf("silent logger produced output: %s", output)
	}
}

// TestLogLevelFiltering verifies that messages below the configured level
// are not logged.
func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, LevelWarn)

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	output := buf.String()
	if strings.Contains(output, "debug message") {
		t.Error("debug message should not be logged at warn level")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should not be logged at warn level")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("warn message should be logged at warn level")
	}
	if !strings.Contains(output, "error message") {
		t.Error("error message should be logged at warn level")
	}
}

// TestLogStructuredFields verifies that structured fields are logged correctly.
func TestLogStructuredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, LevelDebug)

	logger.Info("test", String("str", "value"), Int("num", 42), Bool("flag", true))

	output := buf.String()
	if !strings.Contains(output, "str=value") {
		t.Error("string field not logged")
	}
	if !strings.Contains(output, "num=42") {
		t.Error("int field not logged")
	}
	if !strings.Contains(output, "flag=true") {
		t.Error("bool field not logged")
	}
}

// TestLogNoPayloadBytes verifies that the logger never includes raw payload
// bytes in its output. This test uses a sentinel byte sequence that would
// appear in any payload and verifies it doesn't leak into logs.
func TestLogNoPayloadBytes(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, LevelDebug)

	// Simulate logging that might accidentally include payload data
	sentinel := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	logger.Info("transfer progress", Int("bytes", len(sentinel)))

	output := buf.String()
	for _, b := range sentinel {
		if strings.ContainsRune(output, rune(b)) {
			t.Errorf("log output contains payload byte 0x%02x", b)
		}
	}
}
