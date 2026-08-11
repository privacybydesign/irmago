package sessiontest

import (
	"testing"
)

// TestSessionHandler runs all session handler tests across all protocols.
func TestSessionHandler(t *testing.T) {
	t.Run("openid4vp/irma-sdjwt", testSessionHandlerForOpenID4VPWithIrmaSdJwts)
	t.Run("openid4vp/dc-api", testSessionHandlerForOpenID4VPOverDcApi)
	t.Run("openid4vp/dc-api/eudi-verifier", testSessionHandlerForOpenID4VPOverDcApiWithEudiVerifier)
	t.Run("openid4vp/dc-api/mdoc", testSessionHandlerForOpenID4VPOverDcApiWithMdoc)
	t.Run("openid4vp/sdjwtvc", testSessionHandlerForOpenID4VPWithSdJwtVcs)
	t.Run("openid4vp/mdoc-av", testSessionHandlerForOpenID4VPWithMdocAv)
	t.Run("openid4vci/sdjwtvc/pre-authorized", testSessionHandlerForOpenID4VCIPreAuth)
	t.Run("openid4vci/sdjwtvc/status-list", testSessionHandlerForOpenID4VCIStatusList)
	t.Run("openid4vci/sdjwtvc/auth-code", testSessionHandlerForOpenID4VCIAuthCode)
	t.Run("openid4vci/sdjwtvc/eudi-pid-python", testSessionHandlerForEudiPidPythonIssuer)
	t.Run("openid4vci/mdoc/eudi-pid-python", testSessionHandlerForEudiPidPythonIssuerMdoc)
	t.Run("irma/disclosure", testSessionHandlerForIrmaDisclosures)
	t.Run("irma/issuance", testSessionHandlerForIrmaIssuance)
	t.Run("irma/signature", testSessionHandlerForIrmaSignature)
	t.Run("irma/special", testSessionHandlerEdgeCases)
	t.Run("eudi/logs", testSessionHandlerForEudiLogs)
}
