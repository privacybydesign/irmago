package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server/irmaserver"
	"github.com/stretchr/testify/require"
)

// The random blind attribute identifier fix is gated on protocol version 2.9. These tests exercise
// the four cross-version combinations of a patched ("new", speaks 2.9) and an unpatched ("old",
// caps at 2.8) server and client.
//
// The distinction is entirely determined by the negotiated protocol version: a new peer negotiating
// below 2.9 behaves exactly like an old peer. So "old" is simulated by capping the advertised /
// supported maximum at 2.8, and "new" by allowing 2.9. The server side is capped with the
// irmaserver.MaxProtocolVersionOverride test seam (2.9 is not enabled by default); the client side
// is capped via the X-IRMA-MaxProtocolVersion header.
//
// stempas (irma-demo.stemmen) is a non-keyshare credential, so negotiating 2.9 here does not touch
// the pending keyshare 2.9 protocol change.

// TestRandomBlindVersionGate checks that, for each (server, client) version combination, the server
// puts the version-appropriate random blind identifiers on the wire: the corrected identifier only
// when both peers negotiate 2.9, and the historical (legacy, off-by-one) identifier otherwise.
func TestRandomBlindVersionGate(t *testing.T) {
	credID := irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")

	// For stempas the corrected identifier is votingnumber; the legacy computation ran off the end
	// of the attribute slice and yielded nothing.
	corrected := []string{"votingnumber"}
	var legacy []string

	cases := []struct {
		name        string
		serverMax   *irma.ProtocolVersion
		clientMax   *irma.ProtocolVersion
		wantVersion string
		wantIDs     []string
	}{
		{"old-server_old-client", irma.NewVersion(2, 8), irma.NewVersion(2, 8), "2.8", legacy},
		{"new-server_old-client", irma.NewVersion(2, 9), irma.NewVersion(2, 8), "2.8", legacy},
		{"old-server_new-client", irma.NewVersion(2, 8), irma.NewVersion(2, 9), "2.8", legacy},
		{"new-server_new-client", irma.NewVersion(2, 9), irma.NewVersion(2, 9), "2.9", corrected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			irmaserver.MaxProtocolVersionOverride = tc.serverMax
			defer func() { irmaserver.MaxProtocolVersionOverride = nil }()

			irmaServer := StartIrmaServer(t, nil)
			defer irmaServer.Stop()

			request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
				{
					CredentialTypeID: credID,
					Attributes:       map[string]string{"election": "plantsoen"},
				},
			})
			qr, _, _, err := irmaServer.irma.StartSession(request, nil, "")
			require.NoError(t, err)

			// Simulate the client's first GET of the session request, advertising a maximum version.
			transport := irma.NewHTTPTransport(qr.URL, false)
			transport.SetHeader(irma.MinVersionHeader, "2.8")
			transport.SetHeader(irma.MaxVersionHeader, tc.clientMax.String())
			transport.SetHeader(irma.AuthorizationHeader, "testauthtoken")

			var response struct {
				ProtocolVersion *irma.ProtocolVersion `json:"protocolVersion"`
				Request         struct {
					Credentials []struct {
						RandomBlindAttributeTypeIDs []string `json:"randomblindIDs"`
					} `json:"credentials"`
				} `json:"request"`
			}
			require.NoError(t, transport.Get("", &response))

			require.NotNil(t, response.ProtocolVersion)
			require.Equal(t, tc.wantVersion, response.ProtocolVersion.String(), "negotiated protocol version")
			require.Len(t, response.Request.Credentials, 1)
			require.ElementsMatch(t, tc.wantIDs, response.Request.Credentials[0].RandomBlindAttributeTypeIDs,
				"random blind identifiers on the wire")
		})
	}
}

// TestBlindIssuanceProtocol29 runs a full blind issuance session end to end at negotiated protocol
// version 2.9, where the server sends the corrected identifiers and the client verifies against
// them. It reuses the standard blind issuance flow, which asserts that a non-zero random blind
// attribute is actually issued, confirming the corrected-identifier path issues a valid credential.
func TestBlindIssuanceProtocol29(t *testing.T) {
	irmaserver.MaxProtocolVersionOverride = irma.NewVersion(2, 9)
	defer func() { irmaserver.MaxProtocolVersionOverride = nil }()

	testBlindIssuanceSession(t, RequestorServerConfiguration)
}
