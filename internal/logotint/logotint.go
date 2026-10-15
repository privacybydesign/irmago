// Package logotint derives a single brand colour from a bitmap credential
// logo, so the wallet can tint a card for an issuer that publishes no card
// colours of its own.
package logotint

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"  // register decoder
	_ "image/jpeg" // register decoder
	_ "image/png"  // register decoder
	"math"
	"sync"
)

const (
	// sampleSize is the longest side, in pixels, the logo is sampled at.
	sampleSize = 64
	// hueBuckets is the number of hue ranges pixels are counted into.
	hueBuckets = 24
	// maxDecodePixels caps the decoded logo size, so a crafted image header
	// cannot make the decoder allocate gigabytes.
	maxDecodePixels = 4096 * 4096
)

// Dominant returns the dominant colour of a PNG, JPEG or GIF image as
// "#RRGGBB", or "" when the image cannot be decoded or has no clearly
// coloured pixels (a black, white or grey logo yields "").
//
// Pixels that are mostly transparent, near-white, near-black or near-grey are
// ignored; the remaining pixels are counted per hue range, and the colour
// returned is the average of the pixels in the most populated range.
func Dominant(data []byte) string {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxDecodePixels {
		return ""
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return ""
	}

	b := img.Bounds()
	step := max(1, max(b.Dx(), b.Dy())/sampleSize)

	type bucket struct {
		count   int
		r, g, b float64
	}
	var buckets [hueBuckets]bucket

	for y := b.Min.Y; y < b.Max.Y; y += step {
		for x := b.Min.X; x < b.Max.X; x += step {
			r16, g16, b16, a16 := img.At(x, y).RGBA()
			if a16 < 0x8000 {
				continue // mostly transparent
			}
			// Un-premultiply to 0..1.
			a := float64(a16)
			r, g, bl := float64(r16)/a, float64(g16)/a, float64(b16)/a
			h, s, l := hsl(r, g, bl)
			if l > 0.92 || l < 0.08 || s < 0.2 {
				continue // near-white, near-black or near-grey
			}
			i := int(h*hueBuckets) % hueBuckets
			buckets[i].count++
			buckets[i].r += r
			buckets[i].g += g
			buckets[i].b += bl
		}
	}

	best := -1
	for i, bk := range buckets {
		if bk.count > 0 && (best < 0 || bk.count > buckets[best].count) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	bk := buckets[best]
	n := float64(bk.count)
	return fmt.Sprintf("#%02X%02X%02X", to8(bk.r/n), to8(bk.g/n), to8(bk.b/n))
}

func to8(v float64) uint8 {
	return uint8(math.Round(math.Max(0, math.Min(1, v)) * 255))
}

// hsl converts 0..1 RGB to hue (0..1), saturation and lightness.
func hsl(r, g, b float64) (h, s, l float64) {
	mx := math.Max(r, math.Max(g, b))
	mn := math.Min(r, math.Min(g, b))
	l = (mx + mn) / 2
	d := mx - mn
	if d == 0 {
		return 0, 0, l
	}
	if l > 0.5 {
		s = d / (2 - mx - mn)
	} else {
		s = d / (mx + mn)
	}
	switch mx {
	case r:
		h = (g - b) / d
		if g < b {
			h += 6
		}
	case g:
		h = (b-r)/d + 2
	default:
		h = (r-g)/d + 4
	}
	return h / 6, s, l
}

// Cache memoises Dominant per key (a logo URI, or a scheme file path), so a
// credential list does not decode every logo on every render. Safe for
// concurrent use. The zero value is ready to use.
type Cache struct {
	m sync.Map // key -> string
}

// Get returns the cached tint for key, computing it from load() on a miss.
// load is not called on a hit. An empty key is never cached.
func (c *Cache) Get(key string, load func() []byte) string {
	if key == "" {
		return ""
	}
	if v, ok := c.m.Load(key); ok {
		return v.(string)
	}
	data := load()
	if len(data) == 0 {
		return "" // not cached: the logo may simply not be downloaded yet
	}
	tint := Dominant(data)
	c.m.Store(key, tint)
	return tint
}

// Shared is the process-wide tint cache.
var Shared = &Cache{}
