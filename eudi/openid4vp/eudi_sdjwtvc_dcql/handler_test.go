package eudi_sdjwtvc_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/assert"
)

// CanHandleCredentialQuery routes by format + IRMA-shape; it does not touch the
// embedded engine, so a zero-value Handler is enough to exercise it.
func TestCanHandleCredentialQuery(t *testing.T) {
	h := &Handler{}

	mkQuery := func(format string, vcts ...string) dcql.CredentialQuery {
		q := dcql.CredentialQuery{Format: format}
		if vcts != nil {
			q.Meta = &dcql.Meta{VctValues: vcts}
		}
		return q
	}

	cases := []struct {
		name  string
		query dcql.CredentialQuery
		want  bool
	}{
		{"urn vct routes to EUDI", mkQuery("dc+sd-jwt", "urn:eudi:pid:1"), true},
		{"https url vct routes to EUDI", mkQuery("dc+sd-jwt", "https://example.com/foo"), true},
		{"IRMA-style vct does NOT route to EUDI", mkQuery("dc+sd-jwt", "test.test.email"), false},
		{"no vct_values still routes to EUDI", mkQuery("dc+sd-jwt"), true},
		{"vc+sd-jwt is handled by the VCDM handler, not here", mkQuery("vc+sd-jwt", "urn:eudi:pid:1"), false},
		{"non-sd-jwt format rejected", mkQuery("mso_mdoc", "urn:eudi:pid:1"), false},
		{"mixed list with one non-IRMA value routes to EUDI", mkQuery("dc+sd-jwt", "test.test.email", "urn:eudi:pid:1"), true},
		{"all IRMA-style values rejected", mkQuery("dc+sd-jwt", "test.test.email", "test.test.mobilephone"), false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, h.CanHandleCredentialQuery(c.query), c.name)
	}
}

func TestIsIrmaStyleVct(t *testing.T) {
	cases := []struct {
		vct  string
		want bool
	}{
		{"test.test.email", true},                 // 3 non-empty dot segments — IRMA shape
		{"pbdf.sidn-pbdf.irma", true},             // hyphens are fine inside segments
		{"test.test", false},                      // only 2 segments
		{"test.test.email.extra", false},          // 4 segments
		{"test..email", false},                    // empty middle segment
		{".test.email", false},                    // empty leading segment
		{"test.test.", false},                     // empty trailing segment
		{"urn:eudi:pid:1", false},                 // URN — colons rule out IRMA shape
		{"https://issuer.example.com/foo", false}, // URL with slashes and colons
		{"a.b:c.d", false},                        // a colon anywhere disqualifies
		{"", false},                               // empty string
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isIrmaStyleVct(c.vct), "vct=%q", c.vct)
	}
}
