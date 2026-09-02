package openid4vp

import (
	"crypto/x509"
	"time"

	"github.com/privacybydesign/irmago/eudi/scheme"
)

const ClockSkew = 60 * time.Second

// VerifiedRequestor is what the identity gate established about a verifier: how
// it authenticated, and what it says about itself. It carries no judgement on
// how far to trust the verifier — that is the trust ladder's, applied by the
// client once the gate has passed.
type VerifiedRequestor struct {
	// Certificate is the x5c end-entity certificate the request's signature
	// verified under, within its validity window and not revoked. Nil for a
	// verifier that authenticated by DID. Whether it chains to an anchor is not
	// the gate's question: an untraceable chain proves nothing about the party,
	// so its holder passes as a legitimate-looking stranger and ranks low.
	Certificate *x509.Certificate

	// DID is the DID the verifier authenticated with, when it did.
	DID string

	// SchemeData is the Yivi scheme extension read off Certificate, when it
	// carries one: legal name, logo and authorized queries. What it is worth
	// depends on whether the certificate anchors, which the client decides — the
	// contents of an unanchored certificate are the party's own word.
	SchemeData *scheme.RelyingPartyRequestor

	// SelfAssertedName is what the verifier calls itself: client_metadata's
	// client_name when present, otherwise a name derived from how it
	// authenticated (the certificate's common name, the response URI's host, the
	// did:web domain). The last resort for display, shown under the warning a
	// low trust level carries.
	SelfAssertedName string
}

// VerifierValidator is the identity gate for a verifier: it parses the
// authorization request, verifies its signature against the key its client_id
// binds it to, and reports how the verifier authenticated. A rejection means the
// wallet does not know who it is talking to; the session fails.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*AuthorizationRequest, *VerifiedRequestor, error)
}
