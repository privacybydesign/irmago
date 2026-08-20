package sdjwtvc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// ============================ SD-JWT VC processing descriptions =====================================

type VerifiedSdJwtVc struct {
	IssuerIdentifier       string
	IssuerSignedJwtPayload IssuerSignedJwtPayload
	Disclosures            []sdjwt.DisclosureContent
	ProcessedSdJwtPayload  sdjwt.ProcessedPayload

	KeyBindingJwt *sdjwt.KeyBindingJwtPayload

	// IssuerCertificate is the certificate attesting the issuer's signing key:
	// the `x5c` leaf for an x5c-header issuer, or the certificate a DID issuer's
	// verification method carries over its key. Nil for a bare DID issuer that
	// carries no such certificate.
	//
	// A certificate here is a claim, not a verdict: the signature verified
	// against it and it was presented within its own validity window, but
	// whether any anchor stands behind it is the trust ladder's question —
	// its certificate channel classifies this leaf against the wallet's
	// anchors, and an unanchored issuer ranks low rather than failing.
	// Surfaced because that channel needs it; the verification itself does
	// not keep it.
	IssuerCertificate *x509.Certificate

	rawSdJwtVc SdJwtVc
}

// ClockSkewInSeconds matches statuslist.ClockSkewSeconds. Kept separate:
// the two are independently specified skew windows (SD-JWT VC time-field
// validation vs. Status List Token time-field validation) that happen to
// coincide at 180s — do not deduplicate them into a shared constant.
const ClockSkewInSeconds = 180

// timeToUnixOrZero returns 0 if t is the zero time (i.e. the claim was missing),
// otherwise returns t.Unix(). This prevents time.Time{}.Unix() (-62135596800)
// from being treated as a real timestamp.
func timeToUnixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// SdJwtVcVerificationContext contains some options and configuration for verifying SD-JWT VCs.
type SdJwtVcVerificationContext struct {
	eudi_jwt.X509VerificationContext

	// Used to obtain the current time in order to verify `iat` and `nbf` etc.
	Clock jwt.Clock

	// Used to verify both JWT components of an SD-JWT VC (issuer signed jwt and kbjwt).
	JwtVerifier sdjwt.JwtVerifier

	VerifyVerifiableCredentialTypeInRequestorInfo bool

	// ExpectedNonce is the nonce from the OpenID4VP authorization request that the KB-JWT nonce
	// must match. This prevents replay attacks by ensuring the presentation was created for this
	// specific request.
	ExpectedNonce string

	// StatusChecker, when set, runs an IETF OAuth Token Status List
	// check after the SD-JWT VC verification succeeds: if the
	// payload carries a `status.status_list` reference, the verifier
	// fetches/verifies the referenced Status List Token and rejects
	// the credential unless the indexed bit reads StatusValid.
	// Nil disables the check.
	StatusChecker *statuslist.Checker

	// ExpectedAudience is the audience from the OpenID4VP authorization request that the KB-JWT aud
	// must match.
	ExpectedAudience string
}

func CreateDefaultVerificationContext(trustedChain []byte) SdJwtVcVerificationContext {
	opts, err := utils.CreateX509VerifyOptionsFromCertChain(trustedChain)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 verification options: %v", err))
	}
	return SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *opts,
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}
}

func (v *VerifiedSdJwtVc) GetRawSdJwtVc() SdJwtVc {
	return v.rawSdJwtVc
}

// ============================= Base SD-JWT VC processing =====================================

// sdJwtVcProcessor is the base processor, used to process and verify an SD-JWT VC for both holder and verifier.
type sdJwtVcProcessor struct {
	verificationContext SdJwtVcVerificationContext
	allowInsecureDidWeb bool

	// didWebHTTPClient overrides the client did:web documents are resolved with.
	// Nil takes the default timeout-bounded one, which is what production uses;
	// a test serving its DID document on loopback sets its own.
	didWebHTTPClient *http.Client
}

// keyBindingProcessor is an interface for processing and verifying the key binding JWT of an SD-JWT VC.
// Implementations differ for holder and verifier processing.
type keyBindingProcessor interface {
	ProcessAndVerifyKeyBindingJwt(
		kbjwt *sdjwt.KeyBindingJwt,
		rawSdJwtVc SdJwtVc,
		holder *IssuerSignedJwtPayload,
	) (*sdjwt.KeyBindingJwtPayload, error)
}

func NewSdJwtVcProcessor(verificationContext SdJwtVcVerificationContext) sdJwtVcProcessor {
	return sdJwtVcProcessor{
		verificationContext: verificationContext,
	}
}

// runStatusListCheck consults the configured StatusChecker (if any)
// for the credential's status reference. Returns nil when no checker
// is configured or when the credential has no status_list reference;
// otherwise returns nil only when the indexed bit reads StatusValid.
//
// Status-fetch / verify / decode errors and any non-Valid status are
// returned to the caller, which will reject the credential. The
// behaviour is fail-closed.
func (v *sdJwtVcProcessor) runStatusListCheck(payload *IssuerSignedJwtPayload) error {
	if v.verificationContext.StatusChecker == nil {
		return nil
	}
	if payload.Status == nil || payload.Status.StatusList == nil {
		return nil
	}
	// context.Background is deliberate: there is no session/request context to
	// thread here — every caller up to irmaclient manufactures its own
	// Background, and this runs post-grant while the holder waits on the result.
	// Both network steps are bounded without a caller context: the status-list
	// GET by the checker's FetchTimeout, and did:web signing-key resolution by
	// the timeout-bounded HTTP client used for DID resolution (didweb.NewHTTPClient).
	// Threading a cancellable context down ~60 ParseAndVerifySdJwtVc call sites
	// would only buy cancel-on-dismiss.
	ctx := context.Background()
	status, err := v.verificationContext.StatusChecker.Check(ctx, *payload.Status.StatusList)
	if err != nil {
		return fmt.Errorf("status list check failed: %w", err)
	}
	if status != statuslist.StatusValid {
		return fmt.Errorf("credential status is %s, not valid", status)
	}
	return nil
}

// ProcessAndVerifySdJwtVc implements chapter 7.1 of the SD-JWT VC specification.
func (v *sdJwtVcProcessor) ProcessAndVerifySdJwtVc(
	sdjwtvc SdJwtVcKb,
	keyBindingProcessor keyBindingProcessor,
) (*VerifiedSdJwtVc, error) {
	issuerSignedJwt, disclosures, rawSdJwtVcSdJwt, rawKbJwt, err := sdjwt.SplitKb(sdjwt.SdJwtKb(sdjwtvc))
	if err != nil {
		return nil, err
	}
	rawSdJwtVc := SdJwtVc(rawSdJwtVcSdJwt)

	verified, err := v.parseAndVerifyIssuerSignedJwt(issuerSignedJwt, disclosures)
	if err != nil {
		return nil, err
	}
	issuerSignedJwtPayload := verified.payload

	kbJwtPayload, err := keyBindingProcessor.ProcessAndVerifyKeyBindingJwt(rawKbJwt, rawSdJwtVc, issuerSignedJwtPayload)
	if err != nil {
		return nil, err
	}

	// Verify the credential is allowed to be issued by the requestor
	// TODO: temporarily disable verification of the VCT against what is allowed in the requestor certificate
	// until we can issue SD-JWT VCs that fit our scheme
	// if v.verificationContext.VerifyVerifiableCredentialTypeInRequestorInfo {
	// 	disclosureKeys := slices.Collect(DisclosureContents(decodedDisclosures).Keys())
	// 	err = requestorInfo.AttestationProvider.VerifySdJwtIssuance(issuerSignedJwtPayload.VerifiableCredentialType, disclosureKeys)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to verify SD-JWT issuance: %v", err)
	// 	}
	// }

	// Token Status List check (draft-ietf-oauth-status-list-15). Skip
	// silently when no checker is configured or the credential carries
	// no status_list reference.
	if err := v.runStatusListCheck(issuerSignedJwtPayload); err != nil {
		return nil, err
	}

	// Valid SD-JWT, optionally with valid key binding JWT, depending on the key binding processor used
	return &VerifiedSdJwtVc{
		IssuerIdentifier:       verified.issuerIdentifier,
		IssuerSignedJwtPayload: *issuerSignedJwtPayload,
		Disclosures:            verified.disclosures,
		KeyBindingJwt:          kbJwtPayload,
		IssuerCertificate:      verified.certificate,
		rawSdJwtVc:             rawSdJwtVc,
		ProcessedSdJwtPayload:  *verified.processed,
	}, nil
}

// verifiedIssuerSignedJwt is everything one verified issuer-signed JWT yields.
// It travels as a struct rather than as a row of positional results because the
// caller needs most of it and the error paths need none of it.
type verifiedIssuerSignedJwt struct {
	payload *IssuerSignedJwtPayload
	// issuerIdentifier is who the credential says issued it, as resolved during
	// verification: the `iss` claim, or the subject of the x5c end-entity
	// certificate when `iss` is absent (SD-JWT VC §2.2.2.3).
	issuerIdentifier string
	// certificate is what the issuer signed with when it identified itself by
	// `x5c` — nil otherwise. The caller passes it on to the trust ladder, which
	// is the only place that cares who the signer is beyond the signature
	// holding up.
	certificate *x509.Certificate
	disclosures []sdjwt.DisclosureContent
	processed   *sdjwt.ProcessedPayload
}

// parseAndVerifyIssuerSignedJwt parses and verifies the issuer signed JWT of an SD-JWT VC,
// including signature verification, issuer identity resolution, time field validation, and
// disclosure processing.
func (v *sdJwtVcProcessor) parseAndVerifyIssuerSignedJwt(
	signedJwt sdjwt.IssuerSignedJwt, disclosures []sdjwt.EncodedDisclosure,
) (*verifiedIssuerSignedJwt, error) {
	token, signature, err := v.decodeJwtAndVerifyIssuerSignature([]byte(signedJwt))
	if err != nil {
		return nil, err
	}

	var vct string
	err = token.Get(VerifiableCredentialTypeKey, &vct)
	if err != nil {
		return nil, errors.New("missing vct field")
	}

	// Get optional fields
	sub, subPresent := token.Subject()
	exp, expPresent := token.Expiration()
	iat, iatPresent := token.IssuedAt()
	nbf, nbfPresent := token.NotBefore()
	iss, issPresent := token.Issuer()

	// Check if the hashing algorithm was specified and supported, or use SHA-256 as default if the claim is not present
	sdAlg := iana.SHA256
	if token.Has(sdjwt.SdAlgKey) {
		if h := getOptional[string](token, sdjwt.SdAlgKey); iana.IsSupportedHashingAlgorithm(iana.HashingAlgorithm(h)) {
			sdAlg = iana.HashingAlgorithm(h)
		} else {
			return nil, fmt.Errorf("unsupported _sd_alg: %s", h)
		}
	}

	var sdRaw, cnfRaw any

	var sd []sdjwt.HashedDisclosure
	err = token.Get(sdjwt.SdKey, &sdRaw)
	if err == nil {
		sd, err = sdjwt.ParseSdField(sdRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sd field: %v", err)
		}
	}

	var cnf *sdjwt.CnfField
	err = token.Get(sdjwt.ConfirmationKey, &cnfRaw)
	if err == nil {
		cnf, err = sdjwt.ParseConfirmField(cnfRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	// Optional Token Status List reference (draft-ietf-oauth-status-list-15 §5.1).
	var status *statuslist.StatusClaim
	if token.Has(StatusKey) {
		status, err = parseStatusClaim(token)
		if err != nil {
			return nil, fmt.Errorf("failed to parse status claim: %v", err)
		}
	}

	// Verify and process disclosures
	// Get structured SD-JWT claims, which we can check for embedded disclosure digests
	issuerSignedJwtClaims, err := sdjwt.ExtractClaimsAndDisclosureDigestsFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from token: %v", err)
	}

	// Construct payload — use 0 for missing time claims instead of time.Time{}.Unix()
	payload := &IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Sd:      sd,
			SdAlg:   iana.HashingAlgorithm(sdAlg),
			Confirm: cnf,
		},
		VerifiableCredentialType: vct,
		Status:                   status,
	}

	issuerIdentifier := ""
	switch {
	case !signature.identifiesIssuer:
		// The issuer's identity is the `iss` claim and nothing may stand in for
		// it: a DID issuer is named by its DID, which DID resolution binds to
		// the signing key. Any attesting certificate it carries says nothing
		// about that name, so it is not consulted here.
		if !issPresent {
			return nil, errors.New("missing iss: issuer cannot be determined without an x5c header")
		}
		payload.Issuer = &iss
		issuerIdentifier = iss
	case issPresent:
		// An x5c-authenticated issuer must not be able to claim an arbitrary identity
		if err := utils.VerifyCertificateUri(signature.certificate, iss); err != nil {
			return nil, fmt.Errorf("iss %q is not a SAN of the issuer certificate: %w", iss, err)
		}
		payload.Issuer = &iss
		issuerIdentifier = iss
	default:
		issuerIdentity, err := utils.ObtainIssuerFromCert(signature.certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain issuer URL from certificate: %v", err)
		}
		issuerIdentifier = issuerIdentity
		// Explicitly do not set payload.Issuer, as this is not part of the JWT claimset.
	}

	if subPresent {
		payload.Subject = &sub
	}

	if expPresent {
		expInt := timeToUnixOrZero(exp)
		payload.Expiry = &expInt
	}

	if iatPresent {
		iatInt := timeToUnixOrZero(iat)
		payload.IssuedAt = &iatInt
	}

	if nbfPresent {
		nbfInt := timeToUnixOrZero(nbf)
		payload.NotBefore = &nbfInt
	}

	// Verify times
	err = v.verifyTimeFields(payload)
	if err != nil {
		return nil, err
	}

	// Parse and verify disclosures
	processedSdJwtPayload, decodedDisclosures, err := sdjwt.VerifyAndProcessDisclosures(payload.SdAlg, &issuerSignedJwtClaims, disclosures)
	if err != nil {
		return nil, err
	}

	// Convert pointer to disclosures to values for return  (TODO: optimize to avoid this copy?)
	decodedDisclosuresValues := make([]sdjwt.DisclosureContent, len(decodedDisclosures))
	for i, discPtr := range decodedDisclosures {
		decodedDisclosuresValues[i] = *discPtr
	}

	return &verifiedIssuerSignedJwt{
		payload:          payload,
		issuerIdentifier: issuerIdentifier,
		certificate:      signature.certificate,
		disclosures:      decodedDisclosuresValues,
		processed:        &processedSdJwtPayload,
	}, nil
}

func (v *sdJwtVcProcessor) verifyTimeFields(issuerSignedJwtPayload *IssuerSignedJwtPayload) error {
	now := v.verificationContext.Clock.Now().Unix()
	minSkewNow := now - ClockSkewInSeconds
	maxSkewNow := now + ClockSkewInSeconds

	iat := issuerSignedJwtPayload.IssuedAt
	exp := issuerSignedJwtPayload.Expiry
	nbf := issuerSignedJwtPayload.NotBefore

	if nbf != nil && maxSkewNow < *nbf {
		return fmt.Errorf("verification before nbf: now: %v + skew: %v < nbf: %v", now, ClockSkewInSeconds, *nbf)
	}

	if iat != nil && maxSkewNow < *iat {
		return fmt.Errorf("verification before issued at: %v + skew: %v < %v", now, ClockSkewInSeconds, *iat)
	}

	if exp != nil && minSkewNow > *exp {
		return fmt.Errorf("verification after expiry of issuer signed jwt: %v - skew: %v > %v", now, ClockSkewInSeconds, *exp)
	}

	return nil
}

// parseStatusClaim reads the `status` claim from a verified jwt.Token
// into the structured form expected by the Token Status List
// pipeline. Only the `status_list` member is parsed in v1; other
// sibling members defined by future specs are silently ignored.
func parseStatusClaim(token jwt.Token) (*statuslist.StatusClaim, error) {
	var raw map[string]any
	if err := token.Get(StatusKey, &raw); err != nil {
		return nil, fmt.Errorf("status claim is not an object: %v", err)
	}
	slRaw, ok := raw["status_list"]
	if !ok {
		// status object present without a status_list member is a
		// well-formed extension point; treat as "no status list
		// reference on this credential".
		return &statuslist.StatusClaim{}, nil
	}
	slMap, ok := slRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status_list is not an object: %T", slRaw)
	}
	idxRaw, ok := slMap["idx"]
	if !ok {
		return nil, fmt.Errorf("status_list.idx missing")
	}
	uriRaw, ok := slMap["uri"]
	if !ok {
		return nil, fmt.Errorf("status_list.uri missing")
	}
	uri, ok := uriRaw.(string)
	if !ok {
		return nil, fmt.Errorf("status_list.uri is not a string: %T", uriRaw)
	}
	var idx uint64
	switch n := idxRaw.(type) {
	case float64:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case int:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case int64:
		if n < 0 {
			return nil, fmt.Errorf("status_list.idx is negative: %v", n)
		}
		idx = uint64(n)
	case uint64:
		idx = n
	default:
		return nil, fmt.Errorf("status_list.idx is not a number: %T", idxRaw)
	}
	return &statuslist.StatusClaim{StatusList: &statuslist.Reference{Index: idx, URI: uri}}, nil
}

// issuerSignature is what verifying the issuer-signed JWT's signature
// established about the signer, beyond the signature holding up.
type issuerSignature struct {
	// certificate attests the issuer's signing key: the `x5c` leaf for an
	// x5c-header issuer, or the certificate a DID issuer's verification method
	// carries over its key (RFC 7517 §4.7). Nil for a bare DID issuer that
	// carries none. A claim, not a verdict: the trust ladder's certificate
	// channel classifies it against the wallet's anchors.
	certificate *x509.Certificate

	// identifiesIssuer is true when the certificate is also where the issuer's
	// *identity* comes from — the issuer authenticated by an `x5c` header rather
	// than by a DID. Only then may `iss` be absent, and only then must a present
	// `iss` be a SAN of the certificate. A DID issuer is named by its DID, which
	// resolution binds to the signing key; an attesting certificate it happens to
	// carry vouches for the key, not for that name, so it must not be read as an
	// identity claim.
	identifiesIssuer bool
}

// Decode the JWT into a token and verify the signature with the key the issuer
// identified itself by: the `x5c` leaf in the header, or the key its DID
// resolves to. The gate is internal validity: the signature must verify against
// that key. Whether any anchor stands behind a certificate is classification
// rather than the gate — an issuer under a root the wallet does not anchor
// passes as a legitimate-looking stranger, and the trust ladder ranks it low.
func (v *sdJwtVcProcessor) decodeJwtAndVerifyIssuerSignature(
	signedJwt []byte,
) (jwt.Token, issuerSignature, error) {
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{SdJwtVcTyp, SdJwtVcTyp_Legacy}, v.allowInsecureDidWeb)
	keyProvider.DidWebHTTPClient = v.didWebHTTPClient

	// Create a context for the verification where we can retrieve the requestor info back
	token, err := jwt.Parse(signedJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(v.verificationContext.Clock),
		jwt.WithAcceptableSkew(ClockSkewInSeconds*time.Second),
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, issuerSignature{}, fmt.Errorf("failed to parse JWT: %v", err)
	}

	// An x5c-header issuer always presents a certificate; a DID issuer presents
	// one only when its verification method carries an attesting x5c. Either way
	// the certificate is gated the same, so the two arms differ only in how they
	// surface it — and in whether it also names the issuer. A key-mismatched
	// attesting x5c has already refused inside the DID key provider — that check
	// needs the verification method's own key.
	switch inner := keyProvider.InnerKeyProvider.(type) {
	case *eudi_jwt.X509KeyProvider:
		cert := inner.GetCert()
		if err := v.gateIssuerCertificate(cert); err != nil {
			return nil, issuerSignature{}, err
		}
		return token, issuerSignature{certificate: cert, identifiesIssuer: true}, nil
	case *eudi_jwt.DidKeyProvider:
		cert := inner.GetCert()
		if cert == nil {
			return token, issuerSignature{}, nil // a bare DID issuer, no attestation
		}
		if err := v.gateIssuerCertificate(cert); err != nil {
			return nil, issuerSignature{}, err
		}
		return token, issuerSignature{certificate: cert}, nil
	default:
		return token, issuerSignature{}, nil
	}
}

// gateIssuerCertificate applies the wallet's certificate policy to an issuer's
// certificate, whichever transport carried it. Expiry and revocation refuse the
// credential; anchoring is deliberately not the gate, except on the strict
// context that reads an authorization off the certificate.
func (v *sdJwtVcProcessor) gateIssuerCertificate(cert *x509.Certificate) error {
	// A fresh credential has no business being signed with an expired
	// certificate, so the gate rejects it. (Classification of *stored* issuer
	// evidence is expiry-tolerant — see TrustModel.Classify.)
	if err := eudi_jwt.CheckCertificateValidAt(
		v.verificationContext.X509VerificationContext, cert, ClockSkewInSeconds*time.Second, "issuer certificate",
	); err != nil {
		return err
	}

	// Revocation is the one certificate failure that stays a gate on every
	// path: the CA went out of its way to withdraw this certificate, which is
	// an act of distrust rather than the absence of trust an unanchored issuer
	// shows, and it is how a compromised issuer is cut off. Asked on its own
	// rather than through VerifyCertificate below because the answer needs no
	// chain: the lists are signed by anchors the wallet already holds.
	if err := eudi_jwt.CheckCertificateNotRevoked(v.verificationContext.X509VerificationContext, cert); err != nil {
		return fmt.Errorf("issuer certificate is refused: %w", err)
	}

	// Verify the SD-JWT against the credentials the issuer is authorized to issue
	// TODO: temporarily disable verification of the VCT against what is allowed in the requestor certificate
	// until we can issue SD-JWT VCs that fit our scheme
	if v.verificationContext.VerifyVerifiableCredentialTypeInRequestorInfo {
		// This path demands the issuer's authorization artifact (the Yivi
		// scheme extension), and an authorization is only worth reading off a
		// certificate an anchor stands behind: grant enforcement stays a hard
		// gate here. Chain building and the key usage check against the pinned
		// anchors are asked only here, because only this path reads the answer
		// — the OpenID4VCI context leaves the flag off and ranks the issuer
		// through TrustModel.Classify instead, so asking unconditionally would
		// build a chain per credential for nobody. Revocation is the
		// exception, checked above on every path. This holds identically for a
		// DID-attested issuer: the transport differs, the authorization does not.
		if err := eudi_jwt.VerifyCertificate(v.verificationContext.X509VerificationContext, cert, nil); err != nil {
			return fmt.Errorf("failed to verify certificate: no trust anchor stands behind the issuer certificate")
		}
		// The artifact itself is not carried out of here — nothing downstream
		// reads it yet (see the disabled VCT check above). Parsing it is still
		// the gate: an issuer whose authorization does not decode has not
		// stated one.
		if _, err := utils.GetRequestorInfoFromCertificate[scheme.AttestationProviderRequestor](cert); err != nil {
			return fmt.Errorf("failed to get requestor info from certificate: %v", err)
		}
	}
	return nil
}

func CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs []*VerifiedSdJwtVc) error {
	for _, verifiedSdJwtVc := range verifiedSdJwtVcs {
		cnf := verifiedSdJwtVc.IssuerSignedJwtPayload.Confirm
		if cnf == nil {
			continue
		}

		duplicateCryptographicKey := slices.ContainsFunc(verifiedSdJwtVcs, func(otherSdJwtVc *VerifiedSdJwtVc) bool {
			return otherSdJwtVc != verifiedSdJwtVc &&
				otherSdJwtVc.IssuerSignedJwtPayload.Confirm != nil &&
				((cnf.Jwk != nil && otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Jwk != nil && jwk.Equal(*otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Jwk, *cnf.Jwk)) ||
					(cnf.Kid != nil && otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Kid != nil && *otherSdJwtVc.IssuerSignedJwtPayload.Confirm.Kid == *cnf.Kid))
		})

		if duplicateCryptographicKey {
			return fmt.Errorf(
				"duplicate cryptographic key binding confirmation found for SD-JWT with vct %q",
				verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
			)
		}
	}

	return nil
}

// ============================= Verifier processing =====================================

type VerifierVerificationProcessor struct {
	sdJwtVcProcessor
	verifierKeyBindingProcessor verifierKeyBindingProcessor
}

type verifierKeyBindingProcessor struct {
	keyBindingRequired  bool
	verificationContext SdJwtVcVerificationContext
}

func NewVerifierVerificationProcessor(keyBindingRequired bool, verificationContext SdJwtVcVerificationContext) *VerifierVerificationProcessor {
	return &VerifierVerificationProcessor{
		sdJwtVcProcessor:            NewSdJwtVcProcessor(verificationContext),
		verifierKeyBindingProcessor: NewVerifierKeyBindingProcessor(keyBindingRequired, verificationContext),
	}
}

func NewVerifierKeyBindingProcessor(keyBindingRequired bool, verificationContext SdJwtVcVerificationContext) verifierKeyBindingProcessor {
	return verifierKeyBindingProcessor{
		keyBindingRequired:  keyBindingRequired,
		verificationContext: verificationContext,
	}
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func (v *VerifierVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*VerifiedSdJwtVc, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &v.verifierKeyBindingProcessor)
}

func (v *verifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(
	kbjwt *sdjwt.KeyBindingJwt,
	rawSdJwtVc SdJwtVc,
	issuerSignedJwtPayload *IssuerSignedJwtPayload,
) (*sdjwt.KeyBindingJwtPayload, error) {
	if v.keyBindingRequired && kbjwt == nil {
		return nil, errors.New("key binding jwt is required, but not present in sdjwtvc")
	} else if kbjwt == nil {
		return nil, nil
	}

	keyBindingJwtPayload, err := v.parseAndVerifyKeyBindingJwt(
		rawSdJwtVc,
		issuerSignedJwtPayload,
		*kbjwt,
	)
	if err != nil {
		return nil, err
	}
	return keyBindingJwtPayload, nil
}

// TODO: check against chapter 7.3 of the SD-JWT VC specification.
func (v *verifierKeyBindingProcessor) parseAndVerifyKeyBindingJwt(
	sdJwtVc SdJwtVc,
	issuerSignedJwtPayload *IssuerSignedJwtPayload,
	kbjwt sdjwt.KeyBindingJwt,
) (*sdjwt.KeyBindingJwtPayload, error) {
	header, _, err := sdjwt.DecodeJwtWithoutCheckingSignature(string(kbjwt))
	if err != nil {
		return nil, err
	}

	// TODO: support kid-based key binding confirmation by resolving the did:jwk from the kid and using the resolved key to verify the KB-JWT signature?
	if issuerSignedJwtPayload.Confirm == nil || issuerSignedJwtPayload.Confirm.Jwk == nil {
		return nil, errors.New("issuer signed jwt is missing holder key (cnf) required to verify kbjwt signature")
	}

	var sigAlg jwa.SignatureAlgorithm
	if alg, ok := header["alg"]; ok {
		if algStr, ok := alg.(string); ok {
			// The accepted set is shared with the rest of JWT verification; see
			// eudi_jwt.SupportedSignatureAlgorithms.
			s, found := eudi_jwt.LookupSupportedSignatureAlgorithm(algStr)
			if !found {
				return nil, fmt.Errorf("unsupported signing algorithm in kbjwt header: %s", algStr)
			}
			sigAlg = s
		} else {
			return nil, fmt.Errorf("unsupported signing algorithm in kbjwt header: %s", alg)
		}
	} else {
		return nil, fmt.Errorf("key binding jwt header is expected to have 'alg' of 'ES256', but has %s (header: %v)", header["alg"], header)
	}

	holderKey := issuerSignedJwtPayload.Confirm.Jwk
	payloadJson, err := v.verificationContext.JwtVerifier.Verify(string(kbjwt), *holderKey, sigAlg)

	if err != nil {
		return nil, fmt.Errorf("invalid kbjwt signature: %v (holder key: %v)", err, holderKey)
	}

	if typ := header["typ"]; typ != sdjwt.KbJwtTyp {
		return nil, fmt.Errorf(
			"key binding jwt header is expected to have 'typ' of '%s', but has %s (header: %v)",
			sdjwt.KbJwtTyp,
			typ,
			header,
		)
	}

	var payload sdjwt.KeyBindingJwtPayload
	err = json.Unmarshal(payloadJson, &payload)
	if err != nil {
		return nil, err
	}

	hash, err := iana.CreateUrlEncodedHash(issuerSignedJwtPayload.SdAlg, string(sdJwtVc))
	if err != nil {
		return nil, err
	}

	if payload.IssuerSignedJwtHash == "" {
		return nil, errors.New("issuer signed jwt hash missing in kbjwt")
	}
	if payload.IssuerSignedJwtHash != hash {
		return nil, fmt.Errorf("issuer signed jwt hash doesn't equal sd_hash found in kbjwt")
	}

	if payload.Nonce != v.verificationContext.ExpectedNonce {
		return nil, fmt.Errorf("kbjwt 'nonce' field was expected to contain '%s', but contained '%s' instead", v.verificationContext.ExpectedNonce, payload.Nonce)
	}

	if payload.Audience != v.verificationContext.ExpectedAudience {
		return nil, fmt.Errorf("kbjwt 'aud' field was expected to contain '%s', but contained '%s' instead", v.verificationContext.ExpectedAudience, payload.Audience)
	}

	now := v.verificationContext.Clock.Now()
	maxSkewNow := now.Unix() + ClockSkewInSeconds

	if payload.IssuedAt == 0 {
		return nil, fmt.Errorf("kbjwt is missing iat field, which is required to prevent replay attacks")
	}
	if payload.IssuedAt > maxSkewNow {
		return nil, fmt.Errorf("kbjwt iat value (%v) was after current time (%v)", payload.IssuedAt, now)
	}

	return &payload, nil
}

// ============================= Holder processing =====================================

type HolderVerificationProcessor struct {
	sdJwtVcProcessor
}

func NewHolderVerificationProcessor(verificationContext SdJwtVcVerificationContext) *HolderVerificationProcessor {
	return &HolderVerificationProcessor{
		sdJwtVcProcessor: NewSdJwtVcProcessor(verificationContext),
	}
}

// SetAllowInsecureDidWeb enables resolving did:web DIDs over HTTP instead of HTTPS.
// This should only be called when developer mode is enabled.
func (v *HolderVerificationProcessor) SetAllowInsecureDidWeb(allow bool) {
	v.allowInsecureDidWeb = allow
}

type holderVerifierKeyBindingProcessor struct{}

func (p *holderVerifierKeyBindingProcessor) ProcessAndVerifyKeyBindingJwt(kbjwt *sdjwt.KeyBindingJwt, rawSdJwtVc SdJwtVc, issuerSignedJwtPayload *IssuerSignedJwtPayload) (*sdjwt.KeyBindingJwtPayload, error) {
	if kbjwt != nil {
		return nil, fmt.Errorf("key binding jwt found in SD-JWT, but holder should not receive one from the issuer")
	}
	return nil, nil
}

// ParseAndVerifySdJwtVc is used to verify an SD-JWT VC using the verification options passed via the context parameter.
func (v *HolderVerificationProcessor) ParseAndVerifySdJwtVc(sdjwtvc SdJwtVcKb) (*VerifiedSdJwtVc, error) {
	return v.sdJwtVcProcessor.ProcessAndVerifySdJwtVc(sdjwtvc, &holderVerifierKeyBindingProcessor{})
}

// ====== Utils ======

func getOptional[T any](token jwt.Token, key string) T {
	var value T
	err := token.Get(key, &value)
	if err != nil {
		return *new(T)
	}
	return value
}
