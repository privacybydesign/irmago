package lote

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// LoteTyp is the `typ` header a signed LoTE carries: Yivi's value for a
// TS 119 602 trusted list in JSON, which JAdES (TS 119 182-1) requires.
const LoteTyp = "tl+jwt"

// ClockSkew matches the wallet's other JWS checks (statuslist.ClockSkewSeconds).
const ClockSkew = 180 * time.Second

// verifiedList is a LoTE whose signature and signing chain held, together with
// the bytes that were verified. The bytes are what gets persisted, so a revoked
// signing certificate invalidates lists already on disk.
type verifiedList struct {
	list   *List
	rawJws []byte
}

// verify checks a compact JAdES-B-B signature over a LoTE and parses the payload.
// JAdES-B-B is the baseline level — a single signature, everything needed to
// validate it in the protected header — so the check is the JWS one, plus the
// `typ` guard that stops a JWS minted for another purpose being replayed as a
// trusted list.
//
// The list's own time bounds are not checked here: a correctly signed but expired
// list is still genuine, it just no longer says anything. The checker applies
// that separately, so a fetch failure and an expiry can be told apart.
func verify(rawJws []byte, x509Context eudi_jwt.X509VerificationContext) (*verifiedList, error) {
	if x509Context == nil {
		return nil, fmt.Errorf("no X509 verification context configured")
	}

	// The shared JWS key provider enforces the `typ` allow-list, rejects an
	// ambiguous key reference (both `x5c` and `kid`), and hands back the
	// end-entity certificate so the chain can be validated against the anchors.
	//
	// WithMessage collects the parsed message from the verification pass, so the
	// signature count is checked without decoding the payload twice.
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{LoteTyp}, false)
	var msg jws.Message
	payload, err := jws.Verify(rawJws, jws.WithKeyProvider(keyProvider), jws.WithMessage(&msg))
	if err != nil {
		return nil, fmt.Errorf("verify signature: %v", err)
	}
	if signatures := msg.Signatures(); len(signatures) != 1 {
		// JAdES-B-B compact serialization carries exactly one signature, and Verify
		// above accepts a document as soon as any one of them holds.
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(signatures))
	}

	// A LoTE is signed with an x5c chain; a `kid`-resolved key would skip the
	// anchor check entirely.
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

	// Annex A wraps the list in a single `LoTE` member.
	var document Document
	if err := json.Unmarshal(payload, &document); err != nil {
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

// VerifySigned re-checks a signed LoTE exactly as the wallet does — one
// signature, the `typ` guard, an `x5c` chain validating against x509Context, and
// the document's own required fields — and returns the list it carries.
//
// It exists for the publisher, and is deliberately the whole check rather than a
// parse-only variant, so there is no way to read a LoTE in this codebase without
// its signature having held. As in the wallet, time bounds are not checked.
func VerifySigned(rawJws []byte, x509Context eudi_jwt.X509VerificationContext) (*List, error) {
	verified, err := verify(rawJws, x509Context)
	if err != nil {
		return nil, err
	}
	return verified.list, nil
}

func (v *verifiedList) current(now time.Time) bool {
	return v.list.SchemeInformation.current(now)
}
