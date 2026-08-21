package lote

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/jades"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// LoteTyp is the `typ` header a signed LoTE carries: Yivi's value for a
// TS 119 602 trusted list in JSON, which JAdES (TS 119 182-1) requires.
const LoteTyp = "tl+jwt"

// ClockSkew matches the wallet's other JWS checks (statuslist.ClockSkewSeconds).
const ClockSkew = 180 * time.Second

// Signed is a signed LoTE: the compact JAdES Baseline B signature encapsulating a
// LoTE document. A Document is something anyone could have written; only a Signed
// is evidence.
//
// Fetch and Store stay []byte: neither has grounds to claim its bytes are a
// signature at all.
type Signed []byte

// verifiedList is a LoTE whose signature and signing chain held, together with
// the bytes that were verified. The bytes are what gets persisted, so a revoked
// signing certificate invalidates lists already on disk.
type verifiedList struct {
	list   *List
	rawJws Signed
}

// verify checks a signed LoTE and parses the document it carries.
//
// eudi/jades checks the signature is a conformant Baseline B; what is left here is
// what JAdES leaves to its caller — the `typ` guard, the anchoring of the signing
// certificate, and the document's own required fields.
//
// The list's own time bounds are not checked here: a correctly signed but expired
// list is still genuine, it just no longer says anything. The checker applies
// that separately, so a fetch failure and an expiry can be told apart.
func verify(rawJws Signed, x509Context eudi_jwt.X509VerificationContext) (*verifiedList, error) {
	if x509Context == nil {
		return nil, fmt.Errorf("no X509 verification context configured")
	}

	signature, err := jades.VerifyBaselineB(rawJws, jades.VerifyOptions{
		AllowedTyps: []string{LoteTyp},
	})
	if err != nil {
		return nil, err
	}

	if err := eudi_jwt.VerifyCertificate(x509Context, signature.Signer, nil); err != nil {
		return nil, fmt.Errorf("validate signing certificate: %v", err)
	}

	// Annex A wraps the list in a single `LoTE` member.
	var document Document
	if err := json.Unmarshal(signature.Payload, &document); err != nil {
		return nil, fmt.Errorf("decode list: %v", err)
	}
	list := document.LoTE

	// SchemeName is this list's identity (clause 6.3.6), which the wallet stores
	// and pins, so a document that does not name itself is unusable. Only the
	// English entry is required — the one language 6.3.6 prescribes a format for.
	if list.SchemeInformation.Identity() == "" {
		return nil, fmt.Errorf("list is missing an English SchemeName entry")
	}
	if list.SchemeInformation.NextUpdate.IsZero() {
		// Without it a list signed years ago and captured is indistinguishable from
		// a current one, so it is refused rather than treated as eternal.
		return nil, fmt.Errorf("list is missing ListAndSchemeInformation.NextUpdate")
	}

	return &verifiedList{list: &list, rawJws: rawJws}, nil
}

// VerifySigned re-checks a signed LoTE exactly as the wallet does — a conformant
// Baseline B signature, the `typ` guard, an `x5c` chain validating against
// x509Context, and the document's own required fields — and returns the list it
// carries. It is the counterpart of Sign.
//
// It exists for the publisher, and is deliberately the whole check rather than a
// parse-only variant, so there is no way to read a LoTE in this codebase without
// its signature having held. As in the wallet, time bounds are not checked.
func VerifySigned(rawJws Signed, x509Context eudi_jwt.X509VerificationContext) (*List, error) {
	verified, err := verify(rawJws, x509Context)
	if err != nil {
		return nil, err
	}
	return verified.list, nil
}

func (v *verifiedList) current(now time.Time) bool {
	return v.list.SchemeInformation.current(now)
}
