package vcdmsdjwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// ClockSkewInSeconds is the tolerance applied when checking time-based claims
// (JWT iat/exp/nbf and the VCDM validity period). It matches
// sdjwtvc.ClockSkewInSeconds (180s); kept as an independent local constant
// rather than shared, so this package does not depend on sdjwtvc.
const ClockSkewInSeconds = 180

// VerificationContext carries the options for verifying an SD-JWT-secured VCDM
// credential. It mirrors sdjwtvc.SdJwtVcVerificationContext so the two policy
// layers configure the same way; the JwtVerifier and Expected* fields are used
// only by verifier-side (disclosure) processing, added later.
type VerificationContext struct {
	eudi_jwt.X509VerificationContext

	// Clock supplies "now" for verifying iat/nbf/exp and the VCDM validity
	// period.
	Clock jwt.Clock

	// JwtVerifier verifies JWT signatures. Unused by holder-side receipt
	// verification (no KB-JWT); reserved for verifier-side disclosure.
	JwtVerifier sdjwt.JwtVerifier

	// ExpectedNonce / ExpectedAudience are the OpenID4VP request values a
	// KB-JWT must echo. Verifier-side only; unused for holder receipt.
	ExpectedNonce    string
	ExpectedAudience string
}

// CreateDefaultVerificationContext builds a VerificationContext that trusts the
// given PEM issuer certificate chain (X.509 root/intermediates) and uses the
// system clock, mirroring sdjwtvc.CreateDefaultVerificationContext.
func CreateDefaultVerificationContext(trustedChain []byte) VerificationContext {
	opts, err := utils.CreateX509VerifyOptionsFromCertChain(trustedChain)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 verification options: %v", err))
	}
	return VerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *opts,
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}
}

// VerifiedSdJwtVcdm is the result of verifying an SD-JWT-secured VCDM
// credential: the validated VCDM document (the disclosed logical document), the
// SD-JWT registered claims that secured it, the disclosures, and — when present
// — the verified key binding JWT.
type VerifiedSdJwtVcdm struct {
	// Document is the disclosed, structurally-validated VCDM 2.0 document.
	Document vcdm.Document

	// RegisteredClaims are the SD-JWT / JWT registered claims from the
	// issuer-signed JWT (iss, sub, iat, exp, nbf, cnf, _sd, _sd_alg).
	RegisteredClaims sdjwt.RegisteredClaims

	// Disclosures are the decoded selective-disclosure values that were
	// merged into Document.
	Disclosures []sdjwt.DisclosureContent

	// ProcessedSdJwtPayload is the full disclosed payload (== Document as a
	// plain map), retained for hashing/storage parity with sdjwtvc.
	ProcessedSdJwtPayload sdjwt.ProcessedPayload

	// KeyBindingJwt is the verified KB-JWT payload, or nil when none is
	// present (the holder-receipt case).
	KeyBindingJwt *sdjwt.KeyBindingJwtPayload

	rawSdJwtVcdm SdJwtVcdm
}

// GetRawSdJwtVcdm returns the raw SD-JWT-secured VCDM credential (issuer-signed
// JWT + disclosures, without any KB-JWT) for storage.
func (v *VerifiedSdJwtVcdm) GetRawSdJwtVcdm() SdJwtVcdm {
	return v.rawSdJwtVcdm
}

// HolderPublicKey resolves the holder confirmation key from the credential's
// `cnf` claim, supporting both the `cnf.jwk` and `cnf.kid` (did:jwk / did:key)
// forms via the shared eudi/sdjwt resolver. Returns an error when no `cnf` is
// present. This is the seam that lets a later disclosure step bind a KB-JWT
// without this layer having to know how the holder key was expressed.
func (v *VerifiedSdJwtVcdm) HolderPublicKey() (jwk.Key, error) {
	_, key, err := sdjwt.ExtractHashingAlgorithmAndHolderPubKey(sdjwt.SdJwt(v.rawSdJwtVcdm))
	return key, err
}

// processor is the base processor shared by holder-side and (future)
// verifier-side verification.
type processor struct {
	verificationContext VerificationContext
	allowInsecureDidWeb bool
}

// keyBindingProcessor processes the KB-JWT of an SD-JWT-secured VCDM
// credential. Implementations differ for holder receipt (must be absent) and
// verifier-side disclosure (must be present and valid). Mirrors the sdjwtvc
// seam so a verifier processor slots in later.
type keyBindingProcessor interface {
	ProcessAndVerifyKeyBindingJwt(
		kbjwt *sdjwt.KeyBindingJwt,
		rawSdJwtVcdm SdJwtVcdm,
		registered *sdjwt.RegisteredClaims,
	) (*sdjwt.KeyBindingJwtPayload, error)
}

func (p *processor) processAndVerify(
	credential SdJwtVcdmKb,
	kbProcessor keyBindingProcessor,
) (*VerifiedSdJwtVcdm, error) {
	issuerSignedJwt, disclosures, rawSdJwt, rawKbJwt, err := sdjwt.SplitKb(sdjwt.SdJwtKb(credential))
	if err != nil {
		return nil, err
	}
	raw := SdJwtVcdm(rawSdJwt)

	registered, document, decodedDisclosures, processed, err := p.parseAndVerifyIssuerSignedJwt(issuerSignedJwt, disclosures)
	if err != nil {
		return nil, err
	}

	kbPayload, err := kbProcessor.ProcessAndVerifyKeyBindingJwt(rawKbJwt, raw, registered)
	if err != nil {
		return nil, err
	}

	return &VerifiedSdJwtVcdm{
		Document:              document,
		RegisteredClaims:      *registered,
		Disclosures:           decodedDisclosures,
		ProcessedSdJwtPayload: *processed,
		KeyBindingJwt:         kbPayload,
		rawSdJwtVcdm:          raw,
	}, nil
}

func (p *processor) parseAndVerifyIssuerSignedJwt(
	signedJwt sdjwt.IssuerSignedJwt,
	disclosures []sdjwt.EncodedDisclosure,
) (*sdjwt.RegisteredClaims, vcdm.Document, []sdjwt.DisclosureContent, *sdjwt.ProcessedPayload, error) {
	// Step 1: verify the issuer signature (X.509 x5c or DID kid) and the `typ`.
	token, err := p.decodeJwtAndVerifyFromHeader([]byte(signedJwt))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Step 2: extract SD-JWT / JWT registered claims and verify JWT time fields.
	registered, err := extractRegisteredClaims(token)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := p.verifyTimeFields(registered); err != nil {
		return nil, nil, nil, nil, err
	}

	// Step 3: verify and merge disclosures into the full logical payload.
	claims, err := sdjwt.ExtractClaimsAndDisclosureDigestsFromToken(token)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to extract claims from token: %v", err)
	}
	processed, decodedDisclosures, err := sdjwt.VerifyAndProcessDisclosures(registered.SdAlg, &claims, disclosures)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Step 4 (cornerstone dispatch): the decoded payload must actually be a
	// VCDM document. A `dc+sd-jwt` carrying an IETF SD-JWT VC verifies its
	// signature fine but is not ours — reject it here rather than mis-validate.
	payload := map[string]any(processed)
	if !vcdm.IsVCDM(payload) {
		return nil, nil, nil, nil, fmt.Errorf(
			"payload is not an SD-JWT-secured VCDM credential (detected data model: %s)", vcdm.Detect(payload))
	}
	document := vcdm.Document(payload)

	// Step 5 (VCDM 2.0 §7.1): structural validation AFTER proof verification.
	if err := document.Validate(); err != nil {
		return nil, nil, nil, nil, err
	}

	// Step 6: point-in-time validity of the VCDM document (validFrom/validUntil).
	now := p.verificationContext.Clock.Now()
	if err := document.VerifyValidityPeriod(now, ClockSkewInSeconds*time.Second); err != nil {
		return nil, nil, nil, nil, err
	}

	// Step 7 (VC-JOSE-COSE §3.2.1): when the JWT `iss` claim is present it MUST
	// equal the VCDM `issuer`.
	if registered.Issuer != "" {
		issuerID, err := document.IssuerID()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if registered.Issuer != issuerID {
			return nil, nil, nil, nil, fmt.Errorf(
				"JWT iss %q does not match VCDM issuer %q", registered.Issuer, issuerID)
		}
	}

	decodedValues := make([]sdjwt.DisclosureContent, len(decodedDisclosures))
	for i, d := range decodedDisclosures {
		decodedValues[i] = *d
	}

	return registered, document, decodedValues, &processed, nil
}

// decodeJwtAndVerifyFromHeader parses the issuer-signed JWT, verifying its
// signature via the shared eudi/jwt key provider (X.509 `x5c` or DID `kid`) and
// its `typ` against the SD-JWT-secured VCDM media types. When an X.509 chain is
// used, the end-entity certificate is additionally verified against the trusted
// roots/intermediates and revocation lists.
func (p *processor) decodeJwtAndVerifyFromHeader(signedJwt []byte) (jwt.Token, error) {
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{MediaTypeVcSdJwt, MediaTypeDcSdJwt}, p.allowInsecureDidWeb)

	token, err := jwt.Parse(signedJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(p.verificationContext.Clock),
		jwt.WithAcceptableSkew(ClockSkewInSeconds*time.Second),
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	// If an X.509 chain was used, validate it against the trust anchors + CRLs.
	// (A DID `kid` resolves its key from the DID document, no chain to check.)
	if x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider); ok {
		cert := x509KeyProvider.GetCert()
		if err := eudi_jwt.VerifyCertificate(p.verificationContext.X509VerificationContext, cert, nil); err != nil {
			return nil, fmt.Errorf("failed to verify certificate: %v", err)
		}
	}

	return token, nil
}

// extractRegisteredClaims reads the SD-JWT / JWT registered claims from a
// verified token. `iss` is optional here (the VCDM `issuer` field is the
// authoritative issuer; iss is cross-checked against it in step 7 when present).
func extractRegisteredClaims(token jwt.Token) (*sdjwt.RegisteredClaims, error) {
	sub, _ := token.Subject()
	iss, _ := token.Issuer()

	sdAlg := iana.SHA256
	if token.Has(sdjwt.SdAlgKey) {
		h := getOptional[string](token, sdjwt.SdAlgKey)
		if !iana.IsSupportedHashingAlgorithm(iana.HashingAlgorithm(h)) {
			return nil, fmt.Errorf("unsupported _sd_alg: %s", h)
		}
		sdAlg = iana.HashingAlgorithm(h)
	}

	var sd []sdjwt.HashedDisclosure
	var sdRaw any
	if err := token.Get(sdjwt.SdKey, &sdRaw); err == nil {
		sd, err = sdjwt.ParseSdField(sdRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse _sd field: %v", err)
		}
	}

	var cnf *sdjwt.CnfField
	var cnfRaw any
	if err := token.Get(sdjwt.ConfirmationKey, &cnfRaw); err == nil {
		cnf, err = sdjwt.ParseConfirmField(cnfRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	registered := &sdjwt.RegisteredClaims{
		Subject: sub,
		Issuer:  iss,
		Sd:      sd,
		SdAlg:   sdAlg,
		Confirm: cnf,
	}

	if exp, ok := token.Expiration(); ok {
		v := timeToUnixOrZero(exp)
		registered.Expiry = &v
	}
	if iat, ok := token.IssuedAt(); ok {
		v := timeToUnixOrZero(iat)
		registered.IssuedAt = &v
	}
	if nbf, ok := token.NotBefore(); ok {
		v := timeToUnixOrZero(nbf)
		registered.NotBefore = &v
	}

	return registered, nil
}

// verifyTimeFields validates the JWT-level iat/exp/nbf claims with clock skew.
// This is the securing-level temporal check; the VCDM validity period
// (validFrom/validUntil) is checked separately on the document.
func (p *processor) verifyTimeFields(registered *sdjwt.RegisteredClaims) error {
	now := p.verificationContext.Clock.Now().Unix()
	minSkewNow := now - ClockSkewInSeconds
	maxSkewNow := now + ClockSkewInSeconds

	if nbf := registered.NotBefore; nbf != nil && maxSkewNow < *nbf {
		return fmt.Errorf("verification before nbf: now %v + skew %v < nbf %v", now, ClockSkewInSeconds, *nbf)
	}
	if iat := registered.IssuedAt; iat != nil && maxSkewNow < *iat {
		return fmt.Errorf("verification before issued at: now %v + skew %v < iat %v", now, ClockSkewInSeconds, *iat)
	}
	if exp := registered.Expiry; exp != nil && minSkewNow > *exp {
		return fmt.Errorf("verification after expiry: now %v - skew %v > exp %v", now, ClockSkewInSeconds, *exp)
	}
	return nil
}

// ============================= Holder processing =====================================

// HolderVerificationProcessor verifies an SD-JWT-secured VCDM credential as
// received by the holder over OpenID4VCI: the issuer signature, disclosures,
// VCDM structure and validity, and that no KB-JWT is present (the issuer must
// not send one).
type HolderVerificationProcessor struct {
	processor
}

func NewHolderVerificationProcessor(verificationContext VerificationContext) *HolderVerificationProcessor {
	return &HolderVerificationProcessor{processor{verificationContext: verificationContext}}
}

// SetAllowInsecureDidWeb enables resolving did:web issuer DIDs over HTTP instead
// of HTTPS. Only for developer mode.
func (v *HolderVerificationProcessor) SetAllowInsecureDidWeb(allow bool) {
	v.allowInsecureDidWeb = allow
}

type holderKeyBindingProcessor struct{}

func (holderKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(
	kbjwt *sdjwt.KeyBindingJwt,
	_ SdJwtVcdm,
	_ *sdjwt.RegisteredClaims,
) (*sdjwt.KeyBindingJwtPayload, error) {
	if kbjwt != nil {
		return nil, errors.New("key binding jwt found in SD-JWT-secured VCDM, but holder should not receive one from the issuer")
	}
	return nil, nil
}

// ParseAndVerifySdJwtVcdm verifies an SD-JWT-secured VCDM credential received by
// the holder, using the options in the verification context.
func (v *HolderVerificationProcessor) ParseAndVerifySdJwtVcdm(credential SdJwtVcdmKb) (*VerifiedSdJwtVcdm, error) {
	return v.processor.processAndVerify(credential, holderKeyBindingProcessor{})
}

// ====== Utils ======

func getOptional[T any](token jwt.Token, key string) T {
	var value T
	if err := token.Get(key, &value); err != nil {
		return *new(T)
	}
	return value
}

// timeToUnixOrZero returns 0 for the zero time (a missing claim) instead of
// time.Time{}.Unix() (a large negative), matching sdjwtvc.
func timeToUnixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
