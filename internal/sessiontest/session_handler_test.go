package sessiontest

import (
	"testing"
)

// TestSessionHandler runs all session handler tests across all protocols.
func TestSessionHandler(t *testing.T) {
	t.Run("openid4vp/irma-sdjwt", testSessionHandlerForOpenID4VPWithIrmaSdJwts)
	t.Run("openid4vp/sdjwtvc", testSessionHandlerForOpenID4VPWithSdJwtVcs)
	t.Run("openid4vci/sdjwtvc/pre-authorized", testSessionHandlerForOpenID4VCIPreAuth)
	t.Run("openid4vci/sdjwtvc/auth-code", testSessionHandlerForOpenID4VCIAuthCode)
	t.Run("irma/disclosure", testSessionHandlerForIrmaDisclosures)
	t.Run("irma/issuance", testSessionHandlerForIrmaIssuance)
	t.Run("irma/signature", testSessionHandlerForIrmaSignature)
	t.Run("irma/special", testSessionHandlerEdgeCases)
	t.Run("eudi/logs", testSessionHandlerForEudiLogs)
}
