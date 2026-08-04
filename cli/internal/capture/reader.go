package capture

import (
	"context"
	"errors"
	"fmt"
	"image"

	"dhow/cli/internal/optical"
)

// Stats accounts for every image a capture produced.
//
// The totals have to add up, and a test checks that they do against a source
// of known length. A drop counter that is approximately right is worse than
// none: an operator reading "12% dropped" will change the frame rate, and if
// the number is wrong they will change it in the wrong direction.
type Stats struct {
	// Images is how many images were taken from the source.
	Images int
	// Dropped is how many were discarded because detection was still busy
	// with an earlier one.
	Dropped int
	// Unreadable is how many held no locatable or decodable symbol.
	Unreadable int
	// Foreign is how many decoded to something that is not a frame of this
	// session: another transfer, a replay, or somebody else's QR code.
	Foreign int
	// Damaged is how many decoded to a frame of this session whose CRC failed.
	Damaged int
	// Repeats is how many carried a frame already accepted.
	Repeats int
	// Frames is how many were handed on to the decoder.
	Frames int
}

// Accounted reports whether every image is in exactly one bucket.
func (s Stats) Accounted() bool {
	return s.Images == s.Dropped+s.Unreadable+s.Foreign+s.Damaged+s.Repeats+s.Frames
}

// Handler receives each frame the capture recovered.
//
// It returns whether the frame was accepted by the decoder. Only an accepted
// frame's position is remembered as a repeat, because a position read out of
// an unauthenticated frame is attacker-chosen; see [Position].
type Handler func(frame []byte) (accepted bool, err error)

// Reader drives a source through detection and into a handler.
type Reader struct {
	// Prefilter names the session frames must belong to.
	Prefilter Prefilter
	// Buffer, when true, reads the source in the background and keeps only
	// the newest image, counting the rest as drops.
	//
	// This is right for a live camera and wrong for a directory: a camera
	// produces images whether or not anybody is reading them, and falling
	// behind one means falling behind all of them, whereas a directory is not
	// going anywhere and dropping from it would discard evidence for no
	// reason.
	Buffer bool
}

// Run reads until the source is exhausted, the context is cancelled, or the
// handler returns an error.
func (r *Reader) Run(ctx context.Context, src Source, handle Handler) (Stats, error) {
	if r.Buffer {
		return r.runBuffered(ctx, src, handle)
	}
	return r.runDirect(ctx, src, handle)
}

// runDirect reads one image at a time, doing nothing else while it works.
func (r *Reader) runDirect(ctx context.Context, src Source, handle Handler) (Stats, error) {
	var stats Stats
	held := make(map[uint64]struct{})

	for {
		img, err := src.Next(ctx)
		if errors.Is(err, ErrExhausted) {
			return stats, nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return stats, nil
			}
			return stats, err
		}
		stats.Images++
		if err := r.consume(img, held, &stats, handle); err != nil {
			return stats, err
		}
	}
}

// runBuffered reads the source in a goroutine and keeps only the newest image.
//
// A camera does not wait. If detection takes longer than the interval between
// captures, something has to be discarded, and the newest image is the most
// useful one to keep: the sender is looping the whole stream, so a stale frame
// carries nothing a fresh one does not, and the fresh one is more likely to
// have been taken while the camera was steady.
func (r *Reader) runBuffered(ctx context.Context, src Source, handle Handler) (Stats, error) {
	type production struct {
		images  int
		dropped int
		err     error
	}

	images := make(chan image.Image, 1)
	done := make(chan production, 1)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		var p production
		defer func() {
			close(images)
			done <- p
		}()
		for {
			img, err := src.Next(ctx)
			if errors.Is(err, ErrExhausted) {
				return
			}
			if err != nil {
				if ctx.Err() == nil {
					p.err = err
				}
				return
			}
			p.images++

			select {
			case images <- img:
				continue
			default:
			}
			// The consumer has not taken the pending image. Replace it, and
			// count whichever one ends up discarded - never neither, so the
			// totals add up.
			select {
			case <-images:
				p.dropped++
			default:
			}
			select {
			case images <- img:
			default:
				p.dropped++
			}
		}
	}()

	var stats Stats
	held := make(map[uint64]struct{})
	var handleErr error
	for img := range images {
		if handleErr != nil {
			// Keep draining so the producer's accounting completes rather
			// than blocking it on a channel nobody will read.
			continue
		}
		if err := r.consume(img, held, &stats, handle); err != nil {
			handleErr = err
			cancel()
		}
	}

	p := <-done
	stats.Images = p.images
	stats.Dropped = p.dropped
	// An image the producer handed over and the consumer skipped after an
	// error is neither delivered nor dropped by the producer's reckoning.
	if delivered := stats.Images - stats.Dropped; delivered > r.processed(stats) {
		stats.Dropped += delivered - r.processed(stats)
	}

	switch {
	case handleErr != nil:
		return stats, handleErr
	case p.err != nil:
		return stats, p.err
	default:
		return stats, nil
	}
}

// processed counts the images the consumer reached a verdict on.
func (r *Reader) processed(s Stats) int {
	return s.Unreadable + s.Foreign + s.Damaged + s.Repeats + s.Frames
}

// consume runs one image through detection, the pre-filter, and the handler.
func (r *Reader) consume(img image.Image, held map[uint64]struct{}, stats *Stats, handle Handler) error {
	result, err := optical.Read(img)
	if err != nil {
		stats.Unreadable++
		return nil
	}

	frame := result.Data
	if err := r.Prefilter.Accept(frame); err != nil {
		switch {
		case errors.Is(err, ErrFrameDamaged):
			stats.Damaged++
		default:
			stats.Foreign++
		}
		return nil
	}

	block, symbol, ok := Position(frame)
	if !ok {
		stats.Foreign++
		return nil
	}
	key := uint64(block)<<32 | uint64(symbol)
	if _, seen := held[key]; seen {
		stats.Repeats++
		return nil
	}

	accepted, err := handle(frame)
	if err != nil {
		return fmt.Errorf("capture: handling frame %d/%d: %w", block, symbol, err)
	}
	if !accepted {
		// The decoder refused it: the MAC did not verify, or it is outside
		// the session's parameters. Not remembered as held, because it was
		// never held.
		stats.Foreign++
		return nil
	}
	held[key] = struct{}{}
	stats.Frames++
	return nil
}
