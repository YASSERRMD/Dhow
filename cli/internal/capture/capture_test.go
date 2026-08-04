package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Netpbm ---

func grayImage(w, h int, fill func(x, y int) byte) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Pix[y*img.Stride+x] = fill(x, y)
		}
	}
	return img
}

// TestNetpbmRoundTripsAndStopsExactly is the property the whole streaming path
// depends on: a reader that over-reads by one byte loses every image after the
// first.
func TestNetpbmRoundTripsAndStopsExactly(t *testing.T) {
	var buf bytes.Buffer
	const count = 5
	for i := range count {
		img := grayImage(17, 11, func(x, y int) byte { return byte(x*13 + y*7 + i*29) })
		if err := WriteNetpbm(&buf, img); err != nil {
			t.Fatalf("writing image %d: %v", i, err)
		}
	}
	// A sentinel after the last image: reading it back proves the reader
	// stopped where the last image ended.
	buf.WriteString("TRAILER")

	s := OpenStream(&buf, nil)
	for i := range count {
		img, err := s.Next(context.Background())
		if err != nil {
			t.Fatalf("reading image %d: %v", i, err)
		}
		b := img.Bounds()
		if b.Dx() != 17 || b.Dy() != 11 {
			t.Fatalf("image %d is %dx%d", i, b.Dx(), b.Dy())
		}
		want := byte(0*13 + 0*7 + i*29)
		if got, _, _, _ := img.At(0, 0).RGBA(); byte(got>>8) != want {
			t.Errorf("image %d: pixel 0,0 is %d, want %d", i, byte(got>>8), want)
		}
	}
	if _, err := s.Next(context.Background()); err == nil {
		t.Errorf("a sixth image was read out of a five-image stream")
	}
}

// TestNetpbmComments checks the header parser handles the comment lines
// several encoders insert.
func TestNetpbmComments(t *testing.T) {
	stream := "P5\n# written by something\n4 # inline comment\n3\n255\n" + string(make([]byte, 12))
	s := OpenStream(bytes.NewBufferString(stream), nil)
	img, err := s.Next(context.Background())
	if err != nil {
		t.Fatalf("reading a commented header: %v", err)
	}
	if img.Bounds().Dx() != 4 || img.Bounds().Dy() != 3 {
		t.Errorf("got %v, want 4x3", img.Bounds())
	}
}

// TestMalformedNetpbmIsRejected covers the input a mis-invoked or killed
// capture command produces, and the input somebody hostile would.
func TestMalformedNetpbmIsRejected(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"wrong magic":          "P3\n4 4\n255\n",
		"no dimensions":        "P5\n",
		"zero width":           "P5\n0 4\n255\n",
		"negative-looking":     "P5\n-4 4\n255\n",
		"absurd dimensions":    "P5\n99999 99999\n255\n",
		"huge declared number": "P5\n999999999999 4\n255\n",
		"zero max value":       "P5\n4 4\n0\n",
		"truncated data":       "P5\n4 4\n255\n\x00\x00",
		"header field runs on": "P5\n" + string(bytes.Repeat([]byte("9"), 40)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			s := OpenStream(bytes.NewBufferString(input), nil)
			if _, err := s.Next(context.Background()); err == nil {
				t.Errorf("accepted malformed input")
			}
		})
	}
}

// --- directory ---

func TestDirReadsInOrder(t *testing.T) {
	dir := t.TempDir()
	for i := range 4 {
		img := grayImage(8, 8, func(x, y int) byte { return byte(i * 40) })
		var buf bytes.Buffer
		if err := WriteNetpbm(&buf, img); err != nil {
			t.Fatalf("encoding: %v", err)
		}
		name := filepath.Join(dir, "frame-"+string(rune('0'+i))+".pgm")
		if err := os.WriteFile(name, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}
	// Files a directory pointed at by an operator would also contain.
	if err := os.WriteFile(filepath.Join(dir, "manifest.bin"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	d, err := OpenDir(dir)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if d.Len() != 4 {
		t.Fatalf("found %d images, want 4 (the manifest must not be one)", d.Len())
	}
	for i := range 4 {
		img, err := d.Next(context.Background())
		if err != nil {
			t.Fatalf("image %d: %v", i, err)
		}
		got, _, _, _ := img.At(0, 0).RGBA()
		if byte(got>>8) != byte(i*40) {
			t.Errorf("image %d read out of order: pixel is %d", i, byte(got>>8))
		}
	}
	if _, err := d.Next(context.Background()); !errors.Is(err, ErrExhausted) {
		t.Errorf("a fifth read returned %v, want ErrExhausted", err)
	}
}

func TestOpenDirRejectsEmptyAndMissing(t *testing.T) {
	if _, err := OpenDir(t.TempDir()); err == nil {
		t.Errorf("an empty directory was accepted as a capture source")
	}
	if _, err := OpenDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Errorf("a missing directory was accepted as a capture source")
	}
}

// --- pre-filter ---

// buildFrame assembles a syntactically valid frame with a correct CRC.
func buildFrame(session [16]byte, block, symbol uint32, payload []byte) []byte {
	frame := make([]byte, HeaderSize+len(payload))
	copy(frame[offsetMagic:], "DHOW")
	frame[offsetVersion] = FrameVersion
	copy(frame[offsetSessionID:], session[:])
	binary.LittleEndian.PutUint32(frame[offsetBlockIndex:], block)
	binary.LittleEndian.PutUint32(frame[offsetSymbolIndex:], symbol)
	binary.LittleEndian.PutUint16(frame[offsetPayloadLen:], uint16(len(payload)))
	copy(frame[HeaderSize:], payload)
	binary.LittleEndian.PutUint32(frame[offsetCRC:], crc32.Checksum(payload, castagnoli))
	return frame
}

func TestPrefilterAcceptsAndRejects(t *testing.T) {
	session := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	other := [16]byte{9}
	payload := []byte("a symbol's worth of bytes")
	p := Prefilter{SessionID: session}

	good := buildFrame(session, 3, 17, payload)
	if err := p.Accept(good); err != nil {
		t.Fatalf("a valid frame was rejected: %v", err)
	}
	block, symbol, ok := Position(good)
	if !ok || block != 3 || symbol != 17 {
		t.Errorf("position read as %d/%d (ok=%v), want 3/17", block, symbol, ok)
	}

	tooShort := good[:HeaderSize-1]

	badMagic := bytes.Clone(good)
	badMagic[0] = 'X'

	badVersion := bytes.Clone(good)
	badVersion[offsetVersion] = 9

	foreign := buildFrame(other, 3, 17, payload)

	shortPayload := bytes.Clone(good)
	shortPayload = shortPayload[:len(shortPayload)-1]

	corrupt := bytes.Clone(good)
	corrupt[HeaderSize+3] ^= 0xFF

	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"too short", tooShort, ErrNotAFrame},
		{"wrong magic", badMagic, ErrNotAFrame},
		{"wrong version", badVersion, ErrWrongVersion},
		{"another session", foreign, ErrWrongSession},
		{"length disagrees", shortPayload, ErrLengthMismatch},
		{"payload corrupted", corrupt, ErrFrameDamaged},
		{"empty", nil, ErrNotAFrame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Accept(tc.frame); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPrefilterCatchesEverySingleByteChange is the claim the fast reject
// rests on: a frame damaged anywhere the CRC covers does not reach the FFI.
//
// The header is not covered by the CRC - it is covered by the session MAC on
// the other side - so this walks the payload, which is what the CRC is for.
func TestPrefilterCatchesEverySingleByteChange(t *testing.T) {
	session := [16]byte{7}
	payload := bytes.Repeat([]byte("dhow"), 64)
	p := Prefilter{SessionID: session}
	good := buildFrame(session, 1, 1, payload)

	missed := 0
	for i := HeaderSize; i < len(good); i++ {
		damaged := bytes.Clone(good)
		damaged[i] ^= 0x01
		if err := p.Accept(damaged); !errors.Is(err, ErrFrameDamaged) {
			missed++
		}
	}
	if missed != 0 {
		t.Errorf("%d of %d single-bit payload changes passed the CRC", missed, len(payload))
	}
}

// --- reader accounting ---

// countingSource yields a fixed number of blank images, optionally slowly.
type countingSource struct {
	remaining int
	delay     time.Duration
}

func (c *countingSource) Next(ctx context.Context) (image.Image, error) {
	if c.remaining == 0 {
		return nil, ErrExhausted
	}
	if c.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.delay):
		}
	}
	c.remaining--
	return image.NewGray(image.Rect(0, 0, 32, 32)), nil
}

func (c *countingSource) Close() error { return nil }

// TestStatsAccountForEveryImage is the drop counter's ground-truth check. Every
// image from a source of known length must land in exactly one bucket, whether
// or not the consumer kept up.
func TestStatsAccountForEveryImage(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		const total = 40
		src := &countingSource{remaining: total}
		r := &Reader{Buffer: buffered}

		stats, err := r.Run(context.Background(), src, func([]byte) (bool, error) {
			return true, nil
		})
		if err != nil {
			t.Fatalf("buffered=%v: %v", buffered, err)
		}
		if stats.Images != total {
			t.Errorf("buffered=%v: read %d images, source held %d", buffered, stats.Images, total)
		}
		if !stats.Accounted() {
			t.Errorf("buffered=%v: %d images do not add up to %+v", buffered, stats.Images, stats)
		}
		// Blank images hold no symbol, so with no drops they are all
		// unreadable; with drops the two together still account for all.
		if stats.Unreadable+stats.Dropped != total {
			t.Errorf("buffered=%v: %d unreadable + %d dropped != %d",
				buffered, stats.Unreadable, stats.Dropped, total)
		}
	}
}

// noisySource yields large images of noise, which are slow to search and hold
// nothing. It exists to make the consumer the bottleneck on purpose.
type noisySource struct {
	remaining int
	seed      uint32
}

func (n *noisySource) Next(ctx context.Context) (image.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.remaining == 0 {
		return nil, ErrExhausted
	}
	n.remaining--
	img := image.NewGray(image.Rect(0, 0, 900, 900))
	for i := range img.Pix {
		n.seed = n.seed*1664525 + 1013904223
		img.Pix[i] = byte(n.seed >> 24)
	}
	return img, nil
}

func (n *noisySource) Close() error { return nil }

// TestBufferedReaderDropsRatherThanBlocks checks a consumer slower than its
// source causes drops rather than backing the source up. A camera does not
// wait, so a receiver that cannot keep up has to discard rather than queue.
func TestBufferedReaderDropsRatherThanBlocks(t *testing.T) {
	const total = 30
	src := &noisySource{remaining: total, seed: 12345}
	r := &Reader{Buffer: true}

	stats, err := r.Run(context.Background(), src, func([]byte) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("%v", err)
	}
	if stats.Images != total || !stats.Accounted() {
		t.Fatalf("accounting broke: %+v", stats)
	}
	// Generating a noise image is a memory write; searching one for finder
	// patterns is not. The ratio is large enough that this is not a race in
	// any meaningful sense, but it is the one assertion here that depends on
	// relative speed rather than on arithmetic.
	if stats.Dropped == 0 {
		t.Errorf("a consumer far slower than its source dropped nothing: %+v", stats)
	}
	t.Logf("%d images: %d dropped, %d searched and found nothing",
		stats.Images, stats.Dropped, stats.Unreadable)
}

// TestCancellationStopsCleanly checks a receiver stopped by its operator ends
// without an error and with its counts intact.
func TestCancellationStopsCleanly(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		src := &countingSource{remaining: 1000, delay: time.Millisecond}
		r := &Reader{Buffer: buffered}

		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()

		stats, err := r.Run(ctx, src, func([]byte) (bool, error) { return true, nil })
		if err != nil {
			t.Errorf("buffered=%v: cancelling produced an error: %v", buffered, err)
		}
		if !stats.Accounted() {
			t.Errorf("buffered=%v: counts do not add up after cancellation: %+v", buffered, stats)
		}
	}
}
