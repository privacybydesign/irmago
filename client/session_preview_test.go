package client

import (
	"net/url"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

func previewRequestors() map[string]*irma.RequestorInfo {
	name := "Webshop Noord"
	return map[string]*irma.RequestorInfo{
		"shop.example.com": {
			ID:        irma.NewRequestorIdentifier("pbdf-requestors.webshop"),
			Name:      irma.NewTranslatedString(&name),
			Hostnames: []string{"shop.example.com"},
		},
	}
}

func irmaRequest(action irma.Action, u string) SessionRequestData {
	return SessionRequestData{Qr: irma.Qr{URL: u, Type: action}, Protocol: clientmodels.Protocol_Irma}
}

func TestPreviewIrmaRegistered(t *testing.T) {
	p := previewSession(irmaRequest(irma.ActionIssuing, "https://shop.example.com/irma/session/abc"), previewRequestors(), "en")
	require.Equal(t, SessionPreviewKind_Issuance, p.Kind)
	require.Equal(t, SessionPreviewKnowledge_Registered, p.Knowledge)
	require.Equal(t, "shop.example.com", p.Host)
	require.NotNil(t, p.Requestor)
	require.Equal(t, "Webshop Noord", p.Requestor.Name)
	require.True(t, p.Requestor.Verified)
}

func TestPreviewIrmaUnregistered(t *testing.T) {
	p := previewSession(irmaRequest(irma.ActionDisclosing, "https://other.example.org/irma/session/abc"), previewRequestors(), "en")
	require.Equal(t, SessionPreviewKind_Disclosure, p.Kind)
	require.Equal(t, SessionPreviewKnowledge_Unregistered, p.Knowledge)
	require.Equal(t, "other.example.org", p.Requestor.Name)
	require.False(t, p.Requestor.Verified)
}

func TestPreviewIrmaSigning(t *testing.T) {
	p := previewSession(irmaRequest(irma.ActionSigning, "https://shop.example.com/irma/session/abc"), previewRequestors(), "en")
	require.Equal(t, SessionPreviewKind_Signature, p.Kind)
}

func TestPreviewIrmaRedirect(t *testing.T) {
	p := previewSession(irmaRequest(irma.ActionRedirect, "https://shop.example.com/irma/session/abc"), previewRequestors(), "en")
	require.Equal(t, SessionPreviewKind_Unknown, p.Kind)
	require.Equal(t, SessionPreviewKnowledge_None, p.Knowledge)
	require.Nil(t, p.Requestor)
}

func openid4vpRequest(query url.Values) SessionRequestData {
	return SessionRequestData{
		Qr:       irma.Qr{URL: "openid4vp://?" + query.Encode(), Type: irma.ActionDisclosing},
		Protocol: clientmodels.Protocol_OpenID4VP,
	}
}

func TestPreviewOpenID4VPHosts(t *testing.T) {
	for clientID, want := range map[string]string{
		"x509_san_dns:verifier.example.eu":                       "verifier.example.eu",
		"redirect_uri:https://rp.example.eu/callback":            "rp.example.eu",
		"decentralized_identifier:did:web:did.example.eu:issuer": "did.example.eu",
		"did:web:did.example.eu%3A8443":                          "did.example.eu",
		"https://plain.example.eu":                               "plain.example.eu",
		// No host in the client_id: the request_uri's.
		"x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk": "requests.example.eu",
	} {
		p := previewSession(openid4vpRequest(url.Values{
			"client_id":   {clientID},
			"request_uri": {"https://requests.example.eu/request/abc"},
		}), previewRequestors(), "en")
		require.Equal(t, SessionPreviewKind_Disclosure, p.Kind, clientID)
		require.Equal(t, SessionPreviewKnowledge_Host, p.Knowledge, clientID)
		require.Equal(t, want, p.Host, clientID)
		// Never a name or logo: nothing is verified yet.
		require.Nil(t, p.Requestor, clientID)
	}
}

func TestPreviewOpenID4VPNothing(t *testing.T) {
	p := previewSession(openid4vpRequest(url.Values{"client_id": {"x509_hash:abc"}}), previewRequestors(), "en")
	require.Equal(t, SessionPreviewKnowledge_None, p.Knowledge)
	require.Equal(t, "", p.Host)
}

func TestPreviewOpenID4VCI(t *testing.T) {
	byValue := SessionRequestData{
		Qr: irma.Qr{URL: "openid-credential-offer://?" + url.Values{
			"credential_offer": {`{"credential_issuer":"https://issuer.example.eu","credential_configuration_ids":["pid"]}`},
		}.Encode(), Type: irma.ActionIssuing},
		Protocol: clientmodels.Protocol_OpenID4VCI,
	}
	p := previewSession(byValue, previewRequestors(), "en")
	require.Equal(t, SessionPreviewKind_Issuance, p.Kind)
	require.Equal(t, SessionPreviewKnowledge_Host, p.Knowledge)
	require.Equal(t, "issuer.example.eu", p.Host)

	byReference := byValue
	byReference.URL = "openid-credential-offer://?" + url.Values{
		"credential_offer_uri": {"https://offers.example.eu/offer/1"},
	}.Encode()
	require.Equal(t, "offers.example.eu", previewSession(byReference, previewRequestors(), "en").Host)
}
