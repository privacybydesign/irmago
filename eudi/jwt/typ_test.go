package eudi_jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// RFC 7515 §4.1.9: a typ without '/' means application/<typ>, and media types
// compare case-insensitively.
func TestTypMatches(t *testing.T) {
	for typ, want := range map[any]bool{
		"vc+sd-jwt":             true,
		"application/vc+sd-jwt": true,
		"VC+SD-JWT":             true,
		"Application/VC+SD-JWT": true,
		"dc+sd-jwt":             false,
		"text/vc+sd-jwt":        false,
		"vc+sd-jwt; foo":        false,
		"":                      false,
		nil:                     false,
		42:                      false,
	} {
		require.Equal(t, want, TypMatches(typ, "vc+sd-jwt"), "typ %v", typ)
	}
	require.True(t, TypMatches("vc+sd-jwt", "application/vc+sd-jwt"))
}
