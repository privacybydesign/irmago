package eudi_vcdm_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwtdcql"
	"github.com/stretchr/testify/assert"
	"gorm.io/datatypes"
)

// CanHandleCredentialQuery routes purely by format and does not touch the
// embedded engine, so a zero-value Handler is enough to exercise it.
func TestCanHandleCredentialQuery(t *testing.T) {
	h := &Handler{}

	assert.True(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{Format: "vc+sd-jwt"}),
		"VCDM handler serves vc+sd-jwt")
	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{Format: "dc+sd-jwt"}),
		"VCDM handler must not serve dc+sd-jwt (that is the SD-JWT VC handler)")
	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{Format: "mso_mdoc"}),
		"VCDM handler must not serve mdoc")
}

// Without display metadata, a VCDM credential is named by its own `name`.
func TestFallbackName_IsTheDocumentName(t *testing.T) {
	batch := &sdjwtdcql.Batch{ProcessedPayload: datatypes.JSON(`{"name": "Alumni card"}`)}
	assert.Equal(t, "Alumni card", fallbackName(batch, "en"))
}
