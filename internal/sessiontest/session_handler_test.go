package sessiontest

import (
	"testing"
)

func TestSessionHandler(t *testing.T) {
	t.Run("disclosure/irma", testSessionHandlerForIrmaDisclosures)
	t.Run("disclosure/openid4vp", testSessionHandlerForOpenID4VPDisclosures)
	t.Run("issuance/irma", testSessionHandlerForIrmaIssuance)
	t.Run("signature", testSessionHandlerForIrmaSignature)
	t.Run("special", testSessionHandlerEdgeCases)
}
