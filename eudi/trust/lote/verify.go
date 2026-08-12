package lote

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// LoteTyp is the `typ` header a signed LoTE carries. JAdES (ETSI TS 119 182-1)
// requires the protected header to state the media type of what was signed;
// this is Yivi's value for a TS 119 602 trusted list in JSON.
const LoteTyp = "tl+jwt"

// ClockSkew is the tolerance applied to the list's own time bounds, matching
// the wallet's other JWS checks (statuslist.ClockSkewSeconds).
const ClockSkew = 180 * time.Second

// verifiedList is a LoTE whose signature and signing chain held, together with
// the bytes that were verified. The bytes are what gets persisted: re-verifying
// a stored list against the anchors in force at read time is cheap, and it
// means a revoked signing certificate invalidates lists already on disk.
type verifiedList struct {
	list   *List
	rawJws []byte
}

// verify checks a compact JAdES-B-B signature over a LoTE and parses the
// payload.
//
// JAdES-B-B is the baseline level: a single signature, everything needed to
// validate it in the protected header, no timestamps or archival material. So
// the check is exactly the JWS one — the `x5c` chain must validate against the
// pinned anchors and the signature must verify under its end-entity key — plus
// the `typ` guard that stops a JWS minted for another purpose from being
// replayed as a trusted list.
//
// The list's own time bounds are NOT checked here. Whether a list is current is
// a property of the list, not of its signature: a correctly signed but expired
// list is still a genuine list, it just no longer says anything. The checker
// applies that separately, so a fetch failure and an expiry can be told apart
// in the log.
func verify(rawJws []byte, x509Context eudi_jwt.X509VerificationContext) (*verifiedList, error) {
	if x509Context == nil {
		return nil, fmt.Errorf("no X509 verification context configured")
	}

	msg, err := jws.Parse(rawJws)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %v", err)
	}
	signatures := msg.Signatures()
	if len(signatures) != 1 {
		// JAdES-B-B compact serialization carries exactly one signature.
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(signatures))
	}
	// Resolve the signing key through the wallet's shared JWS key provider: it
	// enforces the `typ` allow-list and rejects an ambiguous key reference (both
	// `x5c` and `kid`), and it hands the end-entity certificate back so the
	// chain can be validated against the anchors. A signature that verifies
	// under a certificate nobody trusts is worth nothing, so both have to hold.
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{LoteTyp}, false)
	payload, err := jws.Verify(rawJws, jws.WithKeyProvider(keyProvider))
	if err != nil {
		return nil, fmt.Errorf("verify signature: %v", err)
	}

	// A LoTE is signed with an x5c chain; a `kid`-resolved key would skip the
	// anchor check entirely, so anything else the provider accepted is refused
	// here.
	x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider)
	if !ok {
		return nil, fmt.Errorf("missing 'x5c' header")
	}
	cert := x509KeyProvider.GetCert()
	if cert == nil {
		return nil, fmt.Errorf("signature verified but no end-entity certificate was resolved")
	}
	if err := eudi_jwt.VerifyCertificate(x509Context, cert, nil); err != nil {
		return nil, fmt.Errorf("validate signing certificate: %v", err)
	}

	// Annex A wraps the list in a single `LoTE` member, so the payload is the
	// document rather than the list itself.
	var document Document
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("decode list: %v", err)
	}
	list := document.LoTE

	// SchemeName is this list's identity (clause 6.3.6), and the wallet stores
	// and pins it, so a document that does not name itself is unusable rather
	// than merely incomplete. Only the English entry is required: it is the one
	// language clause 6.3.6 prescribes a format for.
	if list.SchemeInformation.Identity() == "" {
		return nil, fmt.Errorf("list is missing an English SchemeName entry")
	}
	if list.SchemeInformation.NextUpdate.IsZero() {
		// Without it the wallet could not tell a current list from one that was
		// signed years ago and captured, so a list that does not say when it
		// stops being current is refused rather than treated as eternal.
		return nil, fmt.Errorf("list is missing ListAndSchemeInformation.NextUpdate")
	}

	return &verifiedList{list: &list, rawJws: rawJws}, nil
}

// current reports whether the list may still be relied on at now, i.e. whether
// it is before its NextUpdate.
func (v *verifiedList) current(now time.Time) bool {
	return v.list.SchemeInformation.current(now)
}
