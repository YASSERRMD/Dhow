// Package display drives the sending screen.
//
// The sender has no back channel: it cannot know which frames the camera
// caught, so it loops the whole stream until the operator stops it. Every pass
// is identical, which is what lets the receiver treat any capture of a frame as
// interchangeable with any other.
//
// # Pacing
//
// Frames are shown at a fixed interval. Too fast and the camera catches a
// frame mid-redraw; too slow and the transfer takes longer than it needs to.
// The right rate depends on the camera's shutter and the screen's refresh, so
// it is a parameter rather than a constant.
//
// Pacing uses a ticker rather than sleeping for the frame interval after each
// draw. Sleeping would let render time accumulate: a draw that takes 5ms would
// make every frame 5ms late, and the drift would compound across a long
// stream. A ticker keeps the schedule absolute.
//
// # Calibration
//
// A stream opens with a calibration pattern and a session fingerprint. The
// pattern gives the operator something static to focus and frame against
// before data starts moving, and the fingerprint lets both operators confirm
// by eye that the receiver is watching the session the sender is showing,
// which no amount of protocol can establish for them.
package display

import (
	"context"
	"fmt"
	"io"
	"time"

	"dhow/cli/internal/ffi"
	"dhow/cli/internal/render"
)

// Default pacing. 10 frames per second is slow enough that a rolling-shutter
// camera catches a whole frame and fast enough to be useful.
const (
	DefaultFPS = 10
	MinFPS     = 1
	MaxFPS     = 120
)

// Config controls a display run.
type Config struct {
	// FPS is how many frames to show per second.
	FPS int
	// Loops limits how many times to cycle the stream. Zero means loop until
	// the context is cancelled, which is the normal operating mode.
	Loops int
	// CalibrationSeconds is how long to hold the calibration pattern before
	// the first frame.
	CalibrationSeconds int
	// SessionID is shown as a fingerprint so operators can match sessions.
	SessionID [16]byte
	// ClearScreen emits terminal escape sequences between frames.
	ClearScreen bool
}

// Validate reports whether the configuration is usable.
func (c Config) Validate() error {
	if c.FPS < MinFPS || c.FPS > MaxFPS {
		return fmt.Errorf("fps must be between %d and %d, got %d", MinFPS, MaxFPS, c.FPS)
	}
	if c.Loops < 0 {
		return fmt.Errorf("loops cannot be negative, got %d", c.Loops)
	}
	if c.CalibrationSeconds < 0 {
		return fmt.Errorf("calibration seconds cannot be negative, got %d", c.CalibrationSeconds)
	}
	return nil
}

// Interval returns the delay between frames.
func (c Config) Interval() time.Duration {
	return time.Second / time.Duration(c.FPS)
}

// Stats reports what a display run did.
type Stats struct {
	// FramesShown counts every frame drawn, including repeats across loops.
	FramesShown int
	// LoopsCompleted counts full passes through the stream.
	LoopsCompleted int
	// Elapsed is the wall-clock duration of the run.
	Elapsed time.Duration
}

// Fingerprint renders a session ID as a short human-comparable string.
//
// Operators read this aloud to each other. It is grouped and truncated for
// that purpose and must never be used as an identifier in a security check;
// the frame MAC is what actually binds a frame to its session.
func Fingerprint(sessionID [16]byte) string {
	const groups = 4
	out := make([]byte, 0, groups*5)
	for i := range groups {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, fmt.Sprintf("%02X%02X", sessionID[i*2], sessionID[i*2+1])...)
	}
	return string(out)
}

// Clear returns the escape sequence that clears the terminal and homes the
// cursor.
//
// Kept as a function rather than printed inline so a caller can suppress it:
// a log capture or a test wants the frames without the control codes.
func Clear() string {
	return "\x1b[2J\x1b[H"
}

// Calibration renders the pattern shown before a transfer begins.
//
// It is a QR code holding a fixed, publicly known string rather than an
// arbitrary image, so the operator can confirm with any phone scanner that the
// screen, distance, and lighting are good enough to read a code of this size
// before committing to a transfer.
func Calibration(w io.Writer, cfg Config, version int, ecc byte) error {
	payload := fmt.Sprintf("DHOW-CALIBRATION session=%s", Fingerprint(cfg.SessionID))

	qr, err := ffi.EncodeQR([]byte(payload), version, ecc)
	if err != nil {
		return fmt.Errorf("encoding calibration pattern: %w", err)
	}

	if cfg.ClearScreen {
		if _, err := io.WriteString(w, Clear()); err != nil {
			return fmt.Errorf("clearing screen: %w", err)
		}
	}
	if err := render.Terminal(w, qr); err != nil {
		return fmt.Errorf("rendering calibration pattern: %w", err)
	}
	_, err = fmt.Fprintf(w,
		"\nCALIBRATION  session %s\nAlign the receiver on this pattern, then the transfer begins.\n",
		Fingerprint(cfg.SessionID))
	return err
}

// Run displays frames until the stream is exhausted or ctx is cancelled.
//
// Cancellation is not an error: an operator stopping a transfer is the normal
// way one ends, since the sender cannot know when the receiver has enough.
func Run(ctx context.Context, w io.Writer, frames [][]byte, cfg Config, version int, ecc byte) (Stats, error) {
	var stats Stats

	if err := cfg.Validate(); err != nil {
		return stats, err
	}
	if len(frames) == 0 {
		return stats, fmt.Errorf("no frames to display")
	}

	start := time.Now()

	if cfg.CalibrationSeconds > 0 {
		if err := Calibration(w, cfg, version, ecc); err != nil {
			return stats, err
		}
		select {
		case <-ctx.Done():
			stats.Elapsed = time.Since(start)
			return stats, nil
		case <-time.After(time.Duration(cfg.CalibrationSeconds) * time.Second):
		}
	}

	// A ticker rather than a sleep after each draw: sleeping would let render
	// time accumulate into drift across a long stream.
	ticker := time.NewTicker(cfg.Interval())
	defer ticker.Stop()

	for loop := 0; cfg.Loops == 0 || loop < cfg.Loops; loop++ {
		for i, frame := range frames {
			select {
			case <-ctx.Done():
				stats.Elapsed = time.Since(start)
				return stats, nil
			case <-ticker.C:
			}

			if err := drawFrame(w, frame, cfg, version, ecc, i, len(frames), loop); err != nil {
				stats.Elapsed = time.Since(start)
				return stats, err
			}
			stats.FramesShown++
		}
		stats.LoopsCompleted++
	}

	stats.Elapsed = time.Since(start)
	return stats, nil
}

// drawFrame renders one frame and its status line.
func drawFrame(w io.Writer, frame []byte, cfg Config, version int, ecc byte, index, total, loop int) error {
	qr, err := ffi.EncodeQR(frame, version, ecc)
	if err != nil {
		return fmt.Errorf("encoding frame %d: %w", index, err)
	}

	if cfg.ClearScreen {
		if _, err := io.WriteString(w, Clear()); err != nil {
			return fmt.Errorf("clearing screen: %w", err)
		}
	}
	if err := render.Terminal(w, qr); err != nil {
		return fmt.Errorf("rendering frame %d: %w", index, err)
	}

	// The status line carries no payload content, only position. A receiver
	// reads the frame, not this; it is for the operator watching the screen.
	_, err = fmt.Fprintf(w, "\nsession %s   frame %d/%d   pass %d\n",
		Fingerprint(cfg.SessionID), index+1, total, loop+1)
	return err
}
