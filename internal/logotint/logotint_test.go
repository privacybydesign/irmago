package logotint

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/stretchr/testify/require"
)

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

func fill(img *image.NRGBA, r image.Rectangle, c color.NRGBA) {
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
}

func TestDominantPicksMostPopulatedHue(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	fill(img, img.Bounds(), color.NRGBA{255, 255, 255, 255})            // white background: ignored
	fill(img, image.Rect(0, 0, 100, 10), color.NRGBA{0, 0, 0, 255})     // black text: ignored
	fill(img, image.Rect(0, 10, 100, 60), color.NRGBA{0, 82, 204, 255}) // blue: largest
	fill(img, image.Rect(0, 60, 100, 80), color.NRGBA{220, 30, 30, 255})
	require.Equal(t, "#0052CC", Dominant(encodePNG(t, img)))
}

func TestDominantIgnoresTransparentPixels(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 50, 50))
	fill(img, img.Bounds(), color.NRGBA{0, 200, 0, 10}) // nearly invisible green
	fill(img, image.Rect(0, 0, 10, 10), color.NRGBA{200, 100, 0, 255})
	require.Equal(t, "#C86400", Dominant(encodePNG(t, img)))
}

func TestDominantJPEG(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	fill(img, img.Bounds(), color.NRGBA{200, 20, 120, 255})
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: 100}))
	tint := Dominant(buf.Bytes())
	require.Len(t, tint, 7)
	require.Equal(t, byte('#'), tint[0])
}

func TestDominantEmpty(t *testing.T) {
	grey := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	fill(grey, grey.Bounds(), color.NRGBA{128, 128, 128, 255})
	require.Equal(t, "", Dominant(encodePNG(t, grey)))
	require.Equal(t, "", Dominant([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)))
	require.Equal(t, "", Dominant(nil))
}

func TestCache(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	fill(img, img.Bounds(), color.NRGBA{0, 82, 204, 255})
	data := encodePNG(t, img)

	var c Cache
	calls := 0
	load := func() []byte { calls++; return data }
	require.Equal(t, "#0052CC", c.Get("k", load))
	require.Equal(t, "#0052CC", c.Get("k", load))
	require.Equal(t, 1, calls)

	// A missing logo is not cached, so it is retried once downloaded.
	require.Equal(t, "", c.Get("later", func() []byte { return nil }))
	require.Equal(t, "#0052CC", c.Get("later", load))
	require.Equal(t, "", c.Get("", load))
}
