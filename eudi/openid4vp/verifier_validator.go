package openid4vp

import (
	"crypto/x509"
	"time"

	"github.com/privacybydesign/irmago/eudi/scheme"
)

const ClockSkew = 60 * time.Second

// VerifiedRequestor is what the identity gate hands the session about a verifier
// whose request checked out: the certificate it presented, and the competing
// accounts of who it is, kept apart by who stands behind them.
//
// Separate fields rather than one collapsed requestor, because they are treated
// differently all the way to the screen: an attested account may render a logo
// and outranks the party's own word, a self-asserted one is shown under the warn
// state and never supplies a logo.
type VerifiedRequestor struct {
	// Certificate attests the verifier's key: the leaf an x5c verifier presented,
	// or the one a DID verifier's verification method carries. Nil for a bare DID.
	// A claim, not a verdict — only an anchored chain confers a rung.
	Certificate *x509.Certificate

	// Attested is what the verifier's certificate says about it — the Yivi scheme
	// extension's account, or the subject's common name under a third-party anchor
	// — present only when an anchor stands behind that certificate. An unanchored
	// certificate's contents are evidentially self-asserted.
	Attested *scheme.RelyingPartyRequestor

	// SelfAssertedName is the verifier's own account of itself: client_metadata's
	// client_name, the common name of an unanchored certificate, or the hostname it
	// is reachable at. Empty when it asserted nothing beyond what is attested.
	//
	// A bare name rather than a requestor, so there is nowhere to put a logo.
	SelfAssertedName string
}

// VerifierValidator is the identity gate for OpenID4VP verifiers: it parses the
// authorization request, verifies that the verifier is who it claims to be, and
// hands back the request together with the accounts the wallet may describe it
// by. An error means the wallet does not know who it is talking to, and the
// session fails as a party validation failure. Anchoring is not part of the gate,
// so a legitimate-looking stranger passes and ranks low.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*AuthorizationRequest, *VerifiedRequestor, error)
}
