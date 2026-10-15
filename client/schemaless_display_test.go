package client

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// An IRMA credential's card styling is only the tint of its scheme logo.
func TestIrmaCredentialDisplay_LogoTintOnly(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.SetNRGBA(x, y, color.NRGBA{0, 82, 204, 255})
		}
	}
	path := filepath.Join(t.TempDir(), "logo.png")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, png.Encode(f, img))
	require.NoError(t, f.Close())

	display := irmaCredentialDisplay(path)
	require.NotNil(t, display)
	require.Equal(t, "#0052CC", display.LogoTint)
	require.Empty(t, display.BackgroundColor)
	require.Empty(t, display.SvgTemplates)

	require.Nil(t, irmaCredentialDisplay(""))
	require.Nil(t, irmaCredentialDisplay(filepath.Join(t.TempDir(), "missing.png")))
}
