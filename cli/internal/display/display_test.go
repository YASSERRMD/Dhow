package display

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		FPS:       50, // fast, so tests do not spend real time
		Loops:     1,
		SessionID: [16]byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89},
	}
}

// frames builds n distinguishable frame payloads.
func frames(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(strings.Repeat("x", 40) + string(rune('A'+i)))
	}
	return out
}

func TestFingerprintIsGroupedAndStable(t *testing.T) {
	id := [16]byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89}
	got := Fingerprint(id)

	if got != Fingerprint(id) {
		t.Error("fingerprint was not stable across calls")
	}
	if want := "ABCD-EF01-2345-6789"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFingerprintsDifferBetweenSessions(t *testing.T) {
	// Operators compare these by eye to confirm both machines are on the same
	// session, so two sessions must not look alike.
	a := Fingerprint([16]byte{1, 2, 3, 4, 5, 6, 7, 8})
	b := Fingerprint([16]byte{1, 2, 3, 4, 5, 6, 7, 9})
	if a == b {
		t.Error("two different sessions produced the same fingerprint")
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"default fps", Config{FPS: DefaultFPS}, true},
		{"minimum fps", Config{FPS: MinFPS}, true},
		{"maximum fps", Config{FPS: MaxFPS}, true},
		{"zero fps", Config{FPS: 0}, false},
		{"negative fps", Config{FPS: -1}, false},
		{"excessive fps", Config{FPS: MaxFPS + 1}, false},
		{"negative loops", Config{FPS: 10, Loops: -1}, false},
		{"negative calibration", Config{FPS: 10, CalibrationSeconds: -1}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.ok && err != nil {
				t.Errorf("valid config rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("invalid config accepted")
			}
		})
	}
}

func TestIntervalMatchesFPS(t *testing.T) {
	for fps, want := range map[int]time.Duration{
		1:   time.Second,
		10:  100 * time.Millisecond,
		100: 10 * time.Millisecond,
	} {
		if got := (Config{FPS: fps}).Interval(); got != want {
			t.Errorf("fps %d: interval = %v, want %v", fps, got, want)
		}
	}
}

func TestRunShowsEveryFrameOnce(t *testing.T) {
	var buf bytes.Buffer
	stats, err := Run(context.Background(), &buf, frames(5), testConfig(), 5, 'M')
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.FramesShown != 5 {
		t.Errorf("showed %d frames, want 5", stats.FramesShown)
	}
	if stats.LoopsCompleted != 1 {
		t.Errorf("completed %d loops, want 1", stats.LoopsCompleted)
	}
}

func TestRunLoopsTheStream(t *testing.T) {
	// The sender has no back channel, so it repeats until stopped. Every pass
	// must cover the whole stream.
	cfg := testConfig()
	cfg.Loops = 3

	var buf bytes.Buffer
	stats, err := Run(context.Background(), &buf, frames(4), cfg, 5, 'M')
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.FramesShown != 12 {
		t.Errorf("showed %d frames, want 12", stats.FramesShown)
	}
	if stats.LoopsCompleted != 3 {
		t.Errorf("completed %d loops, want 3", stats.LoopsCompleted)
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	// An operator stopping a transfer is how one normally ends, so
	// cancellation is not an error.
	cfg := testConfig()
	cfg.Loops = 0 // loop forever

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var buf bytes.Buffer
	stats, err := Run(ctx, &buf, frames(3), cfg, 5, 'M')
	if err != nil {
		t.Fatalf("cancellation reported as an error: %v", err)
	}
	if stats.FramesShown == 0 {
		t.Error("no frames were shown before cancellation")
	}
	if stats.Elapsed == 0 {
		t.Error("elapsed time was not recorded")
	}
}

func TestRunRespectsPacing(t *testing.T) {
	cfg := testConfig()
	cfg.FPS = 20 // 50ms per frame

	var buf bytes.Buffer
	start := time.Now()
	if _, err := Run(context.Background(), &buf, frames(4), cfg, 5, 'M'); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)

	// Four frames at 50ms each cannot finish faster than about 200ms. The
	// upper bound is loose because CI machines are not real-time.
	if elapsed < 150*time.Millisecond {
		t.Errorf("four frames at 20fps took %v, which is too fast to have paced", elapsed)
	}
}

func TestRunRejectsAnEmptyStream(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Run(context.Background(), &buf, nil, testConfig(), 5, 'M'); err == nil {
		t.Error("an empty stream was accepted")
	}
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Run(context.Background(), &buf, frames(2), Config{FPS: 0}, 5, 'M'); err == nil {
		t.Error("an invalid config was accepted")
	}
}

func TestRunReportsAnUnencodableFrame(t *testing.T) {
	// A frame too large for the pinned version is a configuration error the
	// operator can act on, not something to skip silently.
	big := [][]byte{bytes.Repeat([]byte{0xAA}, 4000)}
	var buf bytes.Buffer
	if _, err := Run(context.Background(), &buf, big, testConfig(), 5, 'M'); err == nil {
		t.Error("a frame too large for the pinned version was accepted")
	}
}

func TestOutputCarriesTheSessionFingerprint(t *testing.T) {
	cfg := testConfig()
	var buf bytes.Buffer
	if _, err := Run(context.Background(), &buf, frames(2), cfg, 5, 'M'); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(buf.String(), Fingerprint(cfg.SessionID)) {
		t.Error("the session fingerprint was not shown to the operator")
	}
}

func TestOutputCarriesFrameProgress(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Run(context.Background(), &buf, frames(3), testConfig(), 5, 'M'); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"frame 1/3", "frame 2/3", "frame 3/3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output did not contain %q", want)
		}
	}
}

func TestClearScreenIsOptional(t *testing.T) {
	// A log capture or a test wants frames without control codes.
	cfg := testConfig()

	var plain bytes.Buffer
	if _, err := Run(context.Background(), &plain, frames(2), cfg, 5, 'M'); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("escape sequences appeared with ClearScreen disabled")
	}

	cfg.ClearScreen = true
	var cleared bytes.Buffer
	if _, err := Run(context.Background(), &cleared, frames(2), cfg, 5, 'M'); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(cleared.String(), Clear()) {
		t.Error("no clear sequence appeared with ClearScreen enabled")
	}
}

func TestCalibrationPatternIsShownFirst(t *testing.T) {
	cfg := testConfig()
	cfg.CalibrationSeconds = 0 // Run skips it; call directly instead

	var buf bytes.Buffer
	if err := Calibration(&buf, cfg, 5, 'M'); err != nil {
		t.Fatalf("Calibration: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CALIBRATION") {
		t.Error("the calibration pattern was not labelled")
	}
	if !strings.Contains(out, Fingerprint(cfg.SessionID)) {
		t.Error("the calibration pattern did not carry the session fingerprint")
	}
	if !strings.Contains(out, "██") {
		t.Error("no QR modules were rendered")
	}
}

func TestCalibrationIsDeterministicForASession(t *testing.T) {
	// The operator focuses against a static pattern; it must not shimmer.
	cfg := testConfig()

	var a, b bytes.Buffer
	if err := Calibration(&a, cfg, 5, 'M'); err != nil {
		t.Fatalf("Calibration: %v", err)
	}
	if err := Calibration(&b, cfg, 5, 'M'); err != nil {
		t.Fatalf("Calibration: %v", err)
	}
	if a.String() != b.String() {
		t.Error("two renderings of one calibration pattern differed")
	}
}

func TestCalibrationDiffersBetweenSessions(t *testing.T) {
	one := testConfig()
	two := testConfig()
	two.SessionID = [16]byte{0xFF, 0xEE}

	var a, b bytes.Buffer
	if err := Calibration(&a, one, 5, 'M'); err != nil {
		t.Fatalf("Calibration: %v", err)
	}
	if err := Calibration(&b, two, 5, 'M'); err != nil {
		t.Fatalf("Calibration: %v", err)
	}
	if a.String() == b.String() {
		t.Error("two sessions produced identical calibration patterns")
	}
}

func TestCalibrationHoldsBeforeFrames(t *testing.T) {
	cfg := testConfig()
	cfg.CalibrationSeconds = 1

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var buf bytes.Buffer
	stats, err := Run(ctx, &buf, frames(2), cfg, 5, 'M')
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Cancelled during calibration, so no data frames should have been drawn.
	if stats.FramesShown != 0 {
		t.Errorf("showed %d frames during the calibration hold, want 0", stats.FramesShown)
	}
	if !strings.Contains(buf.String(), "CALIBRATION") {
		t.Error("the calibration pattern was not shown")
	}
}
