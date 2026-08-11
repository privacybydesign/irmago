package openid4vp

import (
	"crypto/x509"
	"time"

	"github.com/privacybydesign/irmago/eudi/scheme"
)

const ClockSkew = 60 * time.Second

// VerifiedRequestor is what the identity gate hands the session about a
// verifier whose request checked out: the certificate it presented, and the
// competing accounts of who it is, kept apart by who stands behind them.
//
// The two accounts are deliberately separate fields rather than one collapsed
// requestor, because they are treated differently all the way to the screen: an
// attested account may render a logo and outranks the party's own word, a
// self-asserted account is shown under the warn state for the user to judge and
// never supplies a logo.
type VerifiedRequestor struct {
	// Certificate is the end-entity certificate the verifier presented, or nil
	// when it identified itself another way (a DID). Presence is a claim, not
	// a verdict: the trust ladder classifies it against the wallet's anchors,
	// and only an anchored chain confers a rung.
	Certificate *x509.Certificate

	// Attested is what the verifier's certificate says about it, present only
	// when an anchor the wallet holds stands behind that certificate: the Yivi
	// scheme extension's account, or the subject's common name for an anchored
	// third-party certificate. Nil when the verifier presented no certificate
	// or a certificate no anchor vouches for — an unanchored certificate's
	// contents are evidentially self-asserted.
	Attested *scheme.RelyingPartyRequestor

	// SelfAssertedName is the verifier's own account of itself: client_metadata's
	// client_name, or the common name of an unanchored certificate, or the
	// hostname it is reachable at. Empty when the verifier asserted nothing
	// beyond what is attested.
	//
	// A bare name, and deliberately not a requestor: this account reaches the
	// user as one string under the warn state, and there is nowhere in it to put
	// a logo — a name the party chose is a claim the user can weigh, a logo is
	// simply believed. The type is what enforces that, rather than a convention
	// each producer has to keep.
	SelfAssertedName string
}

// VerifierValidator is the identity gate for OpenID4VP verifiers: it parses the
// authorization request, verifies that the verifier is who it claims to be
// (the signature verifies against the key its client_id binds it to), and
// hands back the request together with the accounts of the verifier the wallet
// may describe it by. An error means the wallet does not know who it is
// talking to, and the session fails as a party validation failure — anchoring
// is deliberately not part of the gate, so a legitimate-looking stranger
// passes and ranks low rather than failing.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*AuthorizationRequest, *VerifiedRequestor, error)
}
