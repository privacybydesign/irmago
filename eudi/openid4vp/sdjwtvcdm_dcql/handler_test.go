package sdjwtvcdm_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
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

// The profile reads a stored credential's own display from its payload, an
// Open Badges credential's achievement image included, by its expanded types.
func TestDocumentDisplay(t *testing.T) {
	payload := datatypes.JSON(`{"name": "Alumni card", "credentialSubject": {"achievement": {"image": "https://example.com/badge.png"}}}`)

	display := documentDisplay(&sdjwt_dcql.Batch{ProcessedPayload: payload, ExpandedTypes: []string{vcdm.OpenBadgeCredentialType}})
	assert.Equal(t, clientmodels.TranslatedString{"": "Alumni card"}, display.CredentialNames)
	assert.Equal(t, "https://example.com/badge.png", display.CredentialImage)

	assert.Empty(t, documentDisplay(&sdjwt_dcql.Batch{ProcessedPayload: payload}).CredentialImage, "not an Open Badges credential")
	assert.Equal(t, services.VcdmDocumentDisplay{}, documentDisplay(&sdjwt_dcql.Batch{ProcessedPayload: datatypes.JSON(`not json`)}))
}
