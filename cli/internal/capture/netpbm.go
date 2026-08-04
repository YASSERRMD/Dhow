package capture

import (
	"bufio"
	"fmt"
	"image"
	"io"
)

// Netpbm reading, for the pipe a capture command writes into.
//
// The format is a short ASCII header - a magic, width, height, and maximum
// value, whitespace-separated, with comment lines beginning with a hash -
// followed by exactly width by height by channels bytes. P5 is greyscale and
// P6 is colour; both are what `ffmpeg -f image2pipe` writes.
//
// The parser is written here rather than taken from a library for one reason:
// it must consume exactly one image and not a byte more. A decoder that
// buffers ahead loses the start of the next image in a concatenated stream,
// which is what a live capture is. It is also adversarial input in the same
// sense as everything else the receiver reads - a capture command can be
// mis-invoked, can emit a truncated frame when it is killed, and can be
// replaced by something else entirely - so every declared length is checked
// against what remains before anything is allocated.

// maxNetpbmDimension bounds a declared image size.
//
// Sixteen thousand pixels a side is far beyond any camera and still small
// enough that the largest allocation this can be talked into is under a
// gigabyte. Without it a header claiming four billion by four billion is a
// denial of service written in four ASCII digits.
const maxNetpbmDimension = 16384

// readNetpbm reads one P5 or P6 image.
func readNetpbm(r *bufio.Reader) (image.Image, error) {
	magic, err := readToken(r)
	if err != nil {
		return nil, err
	}
	var channels int
	switch magic {
	case "P5":
		channels = 1
	case "P6":
		channels = 3
	default:
		return nil, fmt.Errorf("capture: %q is not a P5 or P6 image", magic)
	}

	width, err := readInt(r)
	if err != nil {
		return nil, err
	}
	height, err := readInt(r)
	if err != nil {
		return nil, err
	}
	maxValue, err := readInt(r)
	if err != nil {
		return nil, err
	}

	if width <= 0 || height <= 0 || width > maxNetpbmDimension || height > maxNetpbmDimension {
		return nil, fmt.Errorf("capture: image declares an implausible size %dx%d", width, height)
	}
	if maxValue <= 0 || maxValue > 65535 {
		return nil, fmt.Errorf("capture: image declares a maximum value of %d", maxValue)
	}

	// The single whitespace byte that separates the header from the data has
	// already been consumed: readToken stops on it and takes it. Consuming
	// another here would eat the first pixel and shift every image in the
	// stream by one byte, which is a picture that still looks almost right.

	bytesPerSample := 1
	if maxValue > 255 {
		bytesPerSample = 2
	}
	data := make([]byte, width*height*channels*bytesPerSample)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("capture: image data is truncated: %w", err)
	}

	// Converted straight to greyscale rather than to an image.RGBA that the
	// detector would immediately convert itself. A capture is thousands of
	// frames and the intermediate copy is the whole frame.
	out := image.NewGray(image.Rect(0, 0, width, height))
	scale := 255.0 / float64(maxValue)
	for i := range width * height {
		var value float64
		switch channels {
		case 1:
			value = float64(sampleAt(data, i, bytesPerSample))
		default:
			r := float64(sampleAt(data, i*3, bytesPerSample))
			g := float64(sampleAt(data, i*3+1, bytesPerSample))
			b := float64(sampleAt(data, i*3+2, bytesPerSample))
			value = 0.299*r + 0.587*g + 0.114*b
		}
		v := value * scale
		if v > 255 {
			v = 255
		}
		out.Pix[i] = byte(v)
	}
	return out, nil
}

// sampleAt reads sample n, which is one or two big-endian bytes.
func sampleAt(data []byte, n, bytesPerSample int) int {
	if bytesPerSample == 1 {
		return int(data[n])
	}
	return int(data[2*n])<<8 | int(data[2*n+1])
}

// readToken reads the next whitespace-delimited token, skipping comments.
func readToken(r *bufio.Reader) (string, error) {
	var token []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			if len(token) > 0 && err == io.EOF {
				return string(token), nil
			}
			return "", err
		}
		switch c {
		case '#':
			// A comment runs to the end of the line, and may appear between
			// any two header fields.
			for {
				c, err := r.ReadByte()
				if err != nil {
					return "", err
				}
				if c == '\n' || c == '\r' {
					break
				}
			}
		case ' ', '\t', '\n', '\r':
			if len(token) > 0 {
				return string(token), nil
			}
		default:
			token = append(token, c)
			if len(token) > 32 {
				return "", fmt.Errorf("capture: image header field is implausibly long")
			}
		}
	}
}

// readInt reads the next token as a non-negative integer.
func readInt(r *bufio.Reader) (int, error) {
	token, err := readToken(r)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range []byte(token) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("capture: %q is not a number in an image header", token)
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, fmt.Errorf("capture: image header declares an implausible number")
		}
	}
	if token == "" {
		return 0, fmt.Errorf("capture: image header is missing a field")
	}
	return n, nil
}

// WriteNetpbm writes an image as a P5 greyscale file.
//
// Present so that a test, and `scripts/optical.sh`, can produce the same
// stream a capture command would without depending on one being installed.
func WriteNetpbm(w io.Writer, img image.Image) error {
	b := img.Bounds()
	if _, err := fmt.Fprintf(w, "P5\n%d %d\n255\n", b.Dx(), b.Dy()); err != nil {
		return err
	}
	row := make([]byte, b.Dx())
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			row[x-b.Min.X] = byte((19595*r + 38470*g + 7471*bl + 1<<15) >> 24)
		}
		if _, err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// decodeImage decodes a single image file of any registered format.
func decodeImage(r *bufio.Reader) (image.Image, error) {
	// Netpbm is not in the standard library's registry, so it is sniffed
	// first; everything else goes through image.Decode.
	magic, err := r.Peek(2)
	if err != nil {
		return nil, err
	}
	if magic[0] == 'P' && (magic[1] == '5' || magic[1] == '6') {
		return readNetpbm(r)
	}
	img, _, err := image.Decode(r)
	return img, err
}
