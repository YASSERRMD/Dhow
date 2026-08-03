// Package render turns QR module grids into something a camera can read.
//
// # Quiet zone
//
// Every rendering surrounds the code with a light margin. The QR
// specification requires four modules; without it a scanner cannot find the
// code's edge against whatever is behind it, and a code drawn flush to the
// edge of a screen is frequently unreadable for that reason alone.
//
// # Scale
//
// A module must land on enough camera pixels to be resolved. The renderer
// therefore takes a scale in output pixels per module rather than a target
// image size: the operator's constraint is "how big is a module on screen",
// which is what determines whether the capture works at a given distance.
package render

import (
	"bufio"
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"

	"dhow/cli/internal/ffi"
)

// QuietZone is the light margin in modules required around a QR code.
const QuietZone = 4

// Terminal block characters. A module is two cells wide because terminal cells
// are roughly twice as tall as they are wide, and a scanner expects a square
// module.
const (
	darkCell  = "██"
	lightCell = "  "
)

// Terminal writes a QR code to w using block characters.
//
// Dark modules are written as filled blocks on a light background, which is
// the polarity a scanner expects. A terminal in a dark colour scheme inverts
// this and will not scan; that is a property of the terminal rather than
// something the renderer can correct, and PNG output exists for that case.
func Terminal(w io.Writer, qr *ffi.QRCode) error {
	bw := bufio.NewWriter(w)

	total := qr.Size + 2*QuietZone
	blank := bytes.Repeat([]byte(lightCell), total)

	for range QuietZone {
		if _, err := bw.Write(blank); err != nil {
			return fmt.Errorf("writing quiet zone: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing quiet zone: %w", err)
		}
	}

	for y := range qr.Size {
		for range QuietZone {
			if _, err := bw.WriteString(lightCell); err != nil {
				return fmt.Errorf("writing row %d: %w", y, err)
			}
		}
		for x := range qr.Size {
			cell := lightCell
			if qr.Dark(x, y) {
				cell = darkCell
			}
			if _, err := bw.WriteString(cell); err != nil {
				return fmt.Errorf("writing row %d: %w", y, err)
			}
		}
		for range QuietZone {
			if _, err := bw.WriteString(lightCell); err != nil {
				return fmt.Errorf("writing row %d: %w", y, err)
			}
		}
		if err := bw.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing row %d: %w", y, err)
		}
	}

	for range QuietZone {
		if _, err := bw.Write(blank); err != nil {
			return fmt.Errorf("writing quiet zone: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing quiet zone: %w", err)
		}
	}

	return bw.Flush()
}

// Image renders a QR code at `scale` pixels per module, including the quiet
// zone.
//
// The result is a paletted image with two entries. Two colours is all a QR
// code has, and keeping it that way means no anti-aliasing or colour
// management step can soften a module edge, which is exactly what makes a
// capture ambiguous.
func Image(qr *ffi.QRCode, scale int) (image.Image, error) {
	if scale < 1 {
		return nil, fmt.Errorf("scale must be at least 1 pixel per module, got %d", scale)
	}

	total := (qr.Size + 2*QuietZone) * scale
	img := image.NewPaletted(
		image.Rect(0, 0, total, total),
		color.Palette{color.White, color.Black},
	)

	for y := range qr.Size {
		for x := range qr.Size {
			if !qr.Dark(x, y) {
				continue
			}
			px := (x + QuietZone) * scale
			py := (y + QuietZone) * scale
			for dy := range scale {
				for dx := range scale {
					img.SetColorIndex(px+dx, py+dy, 1)
				}
			}
		}
	}

	return img, nil
}

// PNG writes a QR code to w as a PNG at `scale` pixels per module.
func PNG(w io.Writer, qr *ffi.QRCode, scale int) error {
	img, err := Image(qr, scale)
	if err != nil {
		return err
	}
	// BestCompression: a QR code is two colours and large flat runs, so it
	// compresses well and the cost is paid once at send time rather than on
	// every frame the receiver reads.
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(w, img); err != nil {
		return fmt.Errorf("encoding PNG: %w", err)
	}
	return nil
}
