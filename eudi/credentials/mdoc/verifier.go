package mdoc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// VERIFIER
// ============================================================

// isoMdocDocumentSignerEKU is the extended key usage ISO/IEC 18013-5 Annex
// B.1.2 requires on a Document Signer certificate: 1.0.18013.5.1.2. Despite
// the registry naming it for the mDL, it is the DS usage for every 18013-5
// doctype rather than driving licences alone — Multipaz stamps it on every DS
// certificate it generates (MdocUtil.kt), and its sibling 1.0.18013.5.1.6 is
// reader authentication.
//
// crypto/x509 has no ExtKeyUsage enum member for it, so on a parsed
// certificate it arrives in UnknownExtKeyUsage rather than ExtKeyUsage.
var isoMdocDocumentSignerEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

// isoGenericMdocDocumentSignerEKU is ISO/IEC 23220-4's document signer usage:
// 1.0.23220.4.1.2. 23220-4 profiles mdocs that are not mobile driving licences,
// which is exactly what eu.europa.ec.av.1 is, so an issuer following it stamps
// this OID rather than 18013-5's mDL-specific one.
//
// Accepted alongside the 18013-5 OID because this package targets mso_mdoc in
// general: enforcing only the mDL usage against non-mDL doctypes would reject
// conformant credentials. Multipaz lists both as first-class in its own OID
// table (ISO_18013_5_MDL_DS and ISO_23220_4_MDOC_DS in asn1/OID.kt).
//
// Note what is deliberately NOT here: the AV Blueprint's own worked example
// carries 1.3.130.2.0.0.1.2, an OID with no basis in the AV profile (which
// specifies no EKU at all and defers to 18013-5 and 23220), none in Multipaz's
// table, and none findable in any published registry. Treating an undocumented
// OID as proof of signing authority would defeat the point of the check, so a
// certificate carrying only that one is still refused — pending confirmation
// from the AV team of what production certificates actually carry.
var isoGenericMdocDocumentSignerEKU = asn1.ObjectIdentifier{1, 0, 23220, 4, 1, 2}

// mdocDocumentSignerEKUs are the extended key usages accepted as evidence that
// a leaf certificate is authorized to sign an MSO.
var mdocDocumentSignerEKUs = []asn1.ObjectIdentifier{
	isoMdocDocumentSignerEKU,
	isoGenericMdocDocumentSignerEKU,
}

// decodeCoseSign1 decodes either COSE_Sign1 serialization into the same
// message type.
//
// ISO 18013-5 puts the bare four-element array at issuerAuth and
// deviceSignature, which is what this package now writes (see issuer.go and
// holder.go). Reading is deliberately more permissive than writing: go-cose's
// Sign1Message insists on the tag-18 prefix and UntaggedSign1Message refuses
// it, so accepting only one form would make the verifier reject real documents
// from whichever party disagrees with us. The tag is outside Sig_structure and
// carries no security meaning, so accepting both costs nothing — everything
// that matters is still checked against the signature afterwards.
func decodeCoseSign1(data []byte) (*cose.Sign1Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty COSE_Sign1")
	}
	// 0xd2 = tag 18, the COSE_Sign1_Tagged prefix.
	if data[0] == 0xd2 {
		var tagged cose.Sign1Message
		if err := tagged.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
		return &tagged, nil
	}
	var untagged cose.UntaggedSign1Message
	if err := untagged.UnmarshalCBOR(data); err != nil {
		return nil, err
	}
	msg := cose.Sign1Message(untagged)
	return &msg, nil
}

// checkDocumentSignerEKU rejects a leaf certificate that is not authorized to
// sign mdocs.
//
// Chaining to a trusted IACA root is not by itself evidence of being a
// document signer. A real trust model issues for several roles beneath one
// root — Yivi's own has a relying-party branch alongside the
// attestation-provider branch — so without this check a certificate issued for
// an unrelated purpose could sign an MSO that the wallet then accepts.
//
// This cannot be folded into x509.VerifyOptions.KeyUsages, which speaks only
// crypto/x509's ExtKeyUsage enum and has no member for the ISO OID. That is
// also why the chain walk still passes ExtKeyUsageAny: its sole job there is to
// stop Go defaulting to ExtKeyUsageServerAuth, not to express a policy.
//
// A certificate with no EKU extension is accepted, because RFC 5280 §4.2.1.12
// gives that the meaning "not restricted as to purpose" — there is nothing to
// contradict. anyExtKeyUsage is accepted for the same reason. What gets
// rejected is a certificate that does enumerate its permitted usages and does
// not include this one.
func checkDocumentSignerEKU(cert *x509.Certificate) error {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return nil
	}
	if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if slices.ContainsFunc(mdocDocumentSignerEKUs, oid.Equal) {
			return nil
		}
	}
	// Subject and serial identify the certificate to whoever runs the issuing
	// CA, which is who has to act on this. The serial is hex, as `openssl x509
	// -serial` and the EJBCA UIs render it, so it can be pasted into a
	// certificate search rather than converted first.
	return fmt.Errorf(
		"document signer certificate is not authorized to sign mdocs: its extended key usage is [%s], which includes neither %s (ISO 18013-5 Annex B.1.2) nor %s (ISO 23220-4) (document signer subject %q, serial %X, issued by %q)",
		extKeyUsagesOf(cert), isoMdocDocumentSignerEKU, isoGenericMdocDocumentSignerEKU,
		cert.Subject.String(), cert.SerialNumber, cert.Issuer.String(),
	)
}

// extKeyUsagesOf renders a certificate's extended key usages for a diagnostic:
// the ones crypto/x509 recognises under their RFC 5280 names, every OID it did
// not recognise verbatim.
//
// What a rejected document signer does claim is the whole diagnosis, because
// the mdoc usages are absent by definition. A certificate carrying clientAuth
// was issued from a TLS profile beneath the right root and needs that profile
// amended — Yivi's own test issuer carries `clientAuth, 1.0.18013.5.1.2` for
// exactly that reason — where one carrying an unregistered OID is a reference
// implementation inventing a usage. Naming only the two OIDs that are missing
// cannot tell those apart, and it is the issuer, not the wallet, that has to
// act on either.
func extKeyUsagesOf(cert *x509.Certificate) string {
	names := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		if name, ok := extKeyUsageNames[eku]; ok {
			names = append(names, name)
			continue
		}
		// Unnamed rather than dropped: that the certificate enumerates
		// something is the point, even when this table has not caught up.
		names = append(names, fmt.Sprintf("ExtKeyUsage(%d)", int(eku)))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		names = append(names, oid.String())
	}
	if len(names) == 0 {
		return "empty"
	}
	return strings.Join(names, ", ")
}

// extKeyUsageNames covers crypto/x509's enum, which has no exported way to
// render itself.
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
}

// Verifier holds the pre-installed trust anchor (IACA root cert)
// Phase 1: our own test self-signed IACA root
// Phase 2: Yivi's own IACA root, manually distributed to verifiers
// Phase 3: EU AV Blueprint root CA (from official AP trust list)
type Verifier struct {
	// verificationOptions supplies the trust anchors a document signer is
	// checked against. It is a function consulted per verification rather
	// than a pool captured at construction, because the wallet rebuilds its
	// trust models on every Configuration.Reload — switching developer mode
	// on and off adds and drops the staging anchors — and rebuilding replaces
	// the pools instead of mutating them. A captured pool therefore goes
	// stale in both directions: it misses anchors that were added, and keeps
	// honouring anchors that were dropped.
	verificationOptions func() x509.VerifyOptions

	// clock, if set, is used instead of time.Now() for certificate
	// validity checks. Defaults to real time when left as the zero
	// value — see currentTime(). Exists so tests can exercise expired /
	// not-yet-valid certificate rejection without needing to wait a year
	// or fake the system clock.
	clock time.Time
}

func NewVerifier(rootCerts []*x509.Certificate) *Verifier {
	// This pool is the trust anchor — only certs that chain to something in here are accepted
	// In Phase 3: this would contain the EU AV Blueprint root CA cert
	pool := x509.NewCertPool()
	for _, c := range rootCerts {
		pool.AddCert(c)
	}
	return NewVerifierFromPool(pool)
}

// NewVerifierFromPool is like NewVerifier but takes an already-built trust-
// root pool directly, so callers that already maintain a *x509.CertPool
// (e.g. the wallet's own trust model) don't need to keep a parallel
// []*x509.Certificate list just to construct a Verifier.
//
// The pool is fixed for the lifetime of the Verifier. Callers whose trust
// anchors can change while the process runs want NewVerifierFromOptions.
func NewVerifierFromPool(rootCerts *x509.CertPool) *Verifier {
	return NewVerifierFromOptions(func() x509.VerifyOptions {
		return x509.VerifyOptions{Roots: rootCerts}
	})
}

// NewVerifierFromOptions builds a Verifier that asks options for its trust
// anchors on every verification, so anchors added or dropped afterwards take
// effect without reconstructing anything.
//
// Both the Roots and the Intermediates of the returned VerifyOptions are
// honoured. That matters for a pinned chain: a trust model keeps the
// self-signed root in Roots and the CA that actually signs document signers
// as an intermediate, so an issuer shipping only its DS certificate in
// x5chain is unverifiable if the intermediates are dropped.
func NewVerifierFromOptions(options func() x509.VerifyOptions) *Verifier {
	return &Verifier{verificationOptions: options}
}

// NewVerifierWithClock is like NewVerifier but pins certificate validity
// checks to a fixed point in time instead of the real system clock. Used
// to test expired / not-yet-valid certificate rejection deterministically,
// without needing to wait a year or mess with the OS clock.
func NewVerifierWithClock(rootCerts []*x509.Certificate, clock time.Time) *Verifier {
	v := NewVerifier(rootCerts)
	v.clock = clock
	return v
}

// currentTime returns the verifier's fake clock if one was set via
// NewVerifierWithClock, otherwise the real current time.
func (v *Verifier) currentTime() time.Time {
	if v.clock.IsZero() {
		return time.Now()
	}
	return v.clock
}

type VerificationResult struct {
	DocType         string
	Attributes      map[string]any
	Valid           bool
	Error           string
	DeviceAuthValid bool // only set by VerifyWithDeviceAuth; Verify leaves it false

	// DeviceKey is the holder's device public key embedded in the MSO's
	// deviceKeyInfo, reconstructed on a best-effort basis: if it can't be
	// decoded, this is left nil rather than failing Verify() itself (the
	// digest/signature checks are the security-critical part of Verify;
	// callers that actually need the device key, e.g. issuance-time
	// holder-binding-key matching, check DeviceKey == nil themselves).
	DeviceKey *ecdsa.PublicKey

	// ValidityInfo mirrors the MSO's own validity window, exposed so
	// callers (e.g. issuance-time storage of IssuedAt/ExpiresAt/NotBefore)
	// don't need to re-decode the MSO themselves.
	ValidityInfo ValidityInfo
}

// RequireElements checks that every element the verifier asked for is actually
// present in a successful result, and must be called by any verifier that cares
// which elements it receives.
//
// Nothing else in this package can do it. The digest check proves that each
// element present is authentic, and deviceAuth proves the holder controls the
// device key and signed this session — but neither covers *which* elements were
// selected: the signature is over the session transcript and the docType, not
// over the disclosed set. A holder can therefore drop an element and still
// produce a document that passes every check here, so "Valid == true" answers
// "is what I received genuine", never "did I receive what I asked for". A
// verifier reading result.Attributes["age_over_18"] without this would see a
// missing element as a zero value and, in the boolean case the AV profile uses,
// read it as false rather than absent.
//
// Extra elements beyond those requested are not an error: they are authentic and
// the holder is free to over-disclose, though a verifier minimising what it
// receives may want to check for them separately.
func (r VerificationResult) RequireElements(elements ...string) error {
	if !r.Valid {
		return fmt.Errorf("verification did not succeed: %s", r.Error)
	}

	var missing []string
	for _, element := range elements {
		if _, ok := r.Attributes[element]; !ok {
			missing = append(missing, element)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("requested element(s) %s were not disclosed", strings.Join(missing, ", "))
	}
	return nil
}

// verifyIssuerAuthAndMSO performs the format-wide trust checks shared by
// every verification entry point:
//  1. Decode COSE_Sign1
//  2. Extract x5chain from header 33
//  3. Walk the cert chain: DS cert → IACA cert → trusted root
//  4. Verify COSE_Sign1 signature using DS cert's public key
//  5. Decode MSO from payload
//  6. Check the MSO's own validityInfo window (validFrom/validUntil)
//
// It does NOT check per-namespace digests or deviceAuth — callers do that
// themselves (Verify for a single known namespace,
// VerifyAllDisclosedNamespaces for every namespace present). Returns a nil
// *MSO alongside a result with Error set on any failure; result.DocType,
// result.DeviceKey, and result.ValidityInfo are always populated on success.
func (v *Verifier) verifyIssuerAuthAndMSO(mdoc *MDoc) (*MSO, VerificationResult) {
	// DocType is deliberately left empty until the MSO has been decoded and its
	// docType matched against the envelope's (step 5c). Seeding it from
	// mdoc.DocType would put an unauthenticated, attacker-controlled string into
	// every failure result, where a caller logging or displaying it would treat
	// it as though verification had vouched for it.
	result := VerificationResult{
		Attributes: make(map[string]any),
	}

	// Step 1: decode COSE_Sign1
	msg, err := decodeCoseSign1(mdoc.IssuerSigned.IssuerAuth)
	if err != nil {
		result.Error = fmt.Sprintf("decode cose: %v", err)
		return nil, result
	}

	// Step 2: extract x5chain from unprotected header 33
	// x5chain = [DS cert DER, IACA cert DER]
	// go-cose decodes [][]byte as []any where each element is []byte
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		result.Error = "no x5chain in issuerAuth header 33"
		return nil, result
	}

	chainRaw, ok := rawVal.([]any)
	if !ok {
		// fallback: single cert
		single, ok2 := rawVal.([]byte)
		if !ok2 {
			result.Error = fmt.Sprintf("x5chain wrong type: %T", rawVal)
			return nil, result
		}
		chainRaw = []any{single}
	}

	if len(chainRaw) == 0 {
		result.Error = "x5chain is empty"
		return nil, result
	}

	// parse all certs: certs[0] = DS cert (leaf), certs[1..] = intermediates (IACA cert)
	certs := make([]*x509.Certificate, 0, len(chainRaw))
	for i, raw := range chainRaw {
		b, ok := raw.([]byte)
		if !ok {
			result.Error = fmt.Sprintf("x5chain[%d] wrong type: %T", i, raw)
			return nil, result
		}
		c, err := x509.ParseCertificate(b)
		if err != nil {
			result.Error = fmt.Sprintf("parse x5chain[%d]: %v", i, err)
			return nil, result
		}
		certs = append(certs, c)
	}

	dsCert := certs[0]

	// build intermediate pool from certs[1..n] (the IACA cert)
	// Intermediates come from two places: the credential's own x5chain
	// (certs[1:], typically the IACA) and the trust model, which may carry
	// the CA that signs document signers as an intermediate beneath a
	// self-signed root. Both are needed — an issuer that ships only its DS
	// certificate cannot be verified without the pinned intermediate. Clone
	// rather than add to the trust model's pool, which is shared with every
	// other verification.
	opts := v.verificationOptions()
	intermediates := x509.NewCertPool()
	if opts.Intermediates != nil {
		intermediates = opts.Intermediates.Clone()
	}
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Step 3: verify the full chain
	// x509.Verify walks: DS cert → intermediates → trusted root
	// This is what prevents a chain attack — attacker's root won't be in Roots
	_, err = dsCert.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   v.currentTime(),
	})
	if err != nil {
		// Name the document signer. The two usual causes — an issuer whose CA
		// is not pinned at all, and one whose chain needs an intermediate that
		// neither x5chain nor the trust model carries — are indistinguishable
		// from the bare x509 error.
		result.Error = fmt.Sprintf(
			"chain verification failed: %v (document signer subject %q, serial %X, issued by %q, x5chain length %d)",
			err, dsCert.Subject.String(), dsCert.SerialNumber, dsCert.Issuer.String(), len(certs),
		)
		return nil, result
	}

	// Step 3b: the chain above proves the DS cert descends from a trusted IACA
	// root. This proves it was issued *as a document signer*, rather than for
	// some other role beneath the same root.
	if err := checkDocumentSignerEKU(dsCert); err != nil {
		result.Error = err.Error()
		return nil, result
	}

	// Step 4: verify COSE_Sign1 signature using DS cert's public key
	// go-cose internally builds the Sig_structure and verifies ECDSA against it
	// NOT the bare MSO bytes — the Sig_structure wrapping is what actually gets signed
	coseverifier, err := cose.NewVerifier(cose.AlgorithmES256, dsCert.PublicKey)
	if err != nil {
		result.Error = fmt.Sprintf("create verifier: %v", err)
		return nil, result
	}
	if err := msg.Verify(nil, coseverifier); err != nil {
		result.Error = fmt.Sprintf("MSO signature invalid: %v", err)
		return nil, result
	}

	// Step 5: decode MSO from payload. Payload is Tag24-wrapped (see
	// issuer.go's Issue) — must unwrap that layer before decoding the MSO
	// map itself, not just cbor.Unmarshal it directly.
	mso, err := tag24Unwrap[MSO](msg.Payload)
	if err != nil {
		result.Error = fmt.Sprintf("decode mso: %v", err)
		return nil, result
	}

	// Step 5b: check the MSO's own validityInfo window (validFrom/validUntil).
	// This is separate from, and in addition to, the X.509 certificate expiry
	// checked in Step 3 above — a cert can still be valid while the specific
	// credential's own claimed validity window has expired (or not started
	// yet), and ISO 18013-5 requires checking both. Uses the same v.currentTime()
	// as the cert chain check, so tests can exercise this deterministically too.
	now := v.currentTime()
	if now.Before(mso.ValidityInfo.ValidFrom) {
		result.Error = fmt.Sprintf("credential not yet valid: validFrom=%s, now=%s",
			mso.ValidityInfo.ValidFrom.Format(time.RFC3339), now.Format(time.RFC3339))
		return nil, result
	}
	if now.After(mso.ValidityInfo.ValidUntil) {
		result.Error = fmt.Sprintf("credential expired: validUntil=%s, now=%s",
			mso.ValidityInfo.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
		return nil, result
	}

	// Step 5c: bind the document's docType to the signed one.
	//
	// MDoc.DocType sits in the document map next to issuerSigned and is covered
	// by nothing — no digest, no signature. MSO.docType is inside the MSO the DS
	// certificate signed. Left uncompared, an attacker who re-labels the envelope
	// gets a Valid result carrying their docType, and callers that read the
	// envelope field believe it: eudi/services' mdoc parser stores it as the
	// credential's VerifiableCredentialType, which is what DCQL doctype_value
	// matching and the scheme's relying-party authorization then key off. So an
	// age-verification credential could be filed and presented as a PID.
	//
	// From here on result.DocType is the signed value, so callers reading it
	// cannot pick up the envelope's claim by accident.
	if mdoc.DocType != mso.DocType {
		result.Error = fmt.Sprintf(
			"docType mismatch: document envelope says %q but the signed MSO says %q",
			mdoc.DocType, mso.DocType,
		)
		return nil, result
	}
	result.DocType = mso.DocType

	result.ValidityInfo = mso.ValidityInfo

	// Best-effort: reconstruct the device public key embedded in the MSO.
	// Left nil on failure rather than failing verification outright — see
	// VerificationResult.DeviceKey's doc comment.
	if devicePub, err := ecdsaPublicKeyFromCOSE(mso.DeviceKeyInfo.DeviceKey); err == nil {
		result.DeviceKey = devicePub
	}

	return &mso, result
}

// DocTypeFromIssuerAuth reads the docType out of the MSO that issuerAuth signs
// over, without verifying anything.
//
// It exists for one caller: an issuer that returns the bare IssuerSigned
// structure OpenID4VCI's mso_mdoc profile specifies sends no envelope docType,
// and MDoc.DocType has to hold something for the envelope-versus-MSO binding in
// Verify to compare. Taking it from the MSO makes that comparison trivially
// true, which is correct precisely because there is no second, unsigned copy to
// disagree with — unlike a Document, where the envelope is attacker-controlled
// and the check is load-bearing. Everything that matters about this value is
// still established afterwards: the caller's Verify re-reads it from the MSO
// only once the Document Signer's signature over it has been checked.
func DocTypeFromIssuerAuth(issuerAuth cbor.RawMessage) (string, error) {
	msg, err := decodeCoseSign1(issuerAuth)
	if err != nil {
		return "", fmt.Errorf("decode cose: %w", err)
	}
	mso, err := tag24Unwrap[MSO](msg.Payload)
	if err != nil {
		return "", fmt.Errorf("decode mso: %w", err)
	}
	return mso.DocType, nil
}

// DeviceKeyFromIssuerAuth reads the device public key the MSO binds a credential
// to, without verifying anything.
//
// It exists so a wallet can find out which device key has to sign a presentation
// before it builds one. That key is the credential's own binding, so the question
// has exactly one right answer and a presentation signed with any other key is
// refused -- which is why resolving the signer from here is preferable to
// resolving it from whatever key record happens to be joined to the stored
// credential. Nothing is trusted on the strength of being read here: the copy the
// device signature is actually checked against is re-read from the MSO by
// VerifyWithDeviceAuth, after the Document Signer's signature over it has been
// checked.
func DeviceKeyFromIssuerAuth(issuerAuth cbor.RawMessage) (*ecdsa.PublicKey, error) {
	msg, err := decodeCoseSign1(issuerAuth)
	if err != nil {
		return nil, fmt.Errorf("decode cose: %w", err)
	}
	mso, err := tag24Unwrap[MSO](msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode mso: %w", err)
	}
	deviceKey, err := ecdsaPublicKeyFromCOSE(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("decode deviceKey: %w", err)
	}
	return deviceKey, nil
}

// verifyNamespaceDigests recomputes SHA-256(Tag24(item)) for each disclosed
// item in items and compares it against nsDigests[item.DigestID]
// (constant-time), returning the decoded elementIdentifier -> elementValue
// map on success. Shared by Verify (single known namespace) and
// VerifyAllDisclosedNamespaces (every namespace present).
func verifyNamespaceDigests(items []Tag24Item, nsDigests map[uint64][]byte) (map[string]any, error) {
	attrs := make(map[string]any, len(items))
	for _, tag24item := range items {
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			return nil, fmt.Errorf("unwrap tag24: %v", err)
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			return nil, fmt.Errorf("unwrap inner: %v", err)
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			return nil, fmt.Errorf("decode item: %v", err)
		}

		// A salt shorter than the ISO floor is refused rather than tolerated.
		// The salt is the only thing standing between an undisclosed element and
		// a verifier that brute-forces it: the MSO carries a digest for every
		// element whether or not the item travels, and for a low-entropy value
		// (age_over_NN is one bit) a short random makes that digest a lookup
		// rather than a commitment. Checked here, on receipt, because the party
		// this protects is the holder — Issue enforces the same floor on the
		// credentials we mint, but says nothing about credentials minted
		// elsewhere, and a trust anchor attests to who an issuer is rather than
		// to whether it implements 18013-5 correctly.
		//
		// Placed before the digest comparison so a defective credential is
		// rejected as defective rather than reported as a digest mismatch.
		if len(item.Random) < minSaltLength {
			return nil, fmt.Errorf(
				"element %s carries a %d-byte random value; ISO/IEC 18013-5 requires at least %d",
				item.ElementIdentifier, len(item.Random), minSaltLength)
		}

		hash := sha256.Sum256(tag24item.EncodedItem)
		expectedDigest, exists := nsDigests[item.DigestID]
		if !exists {
			return nil, fmt.Errorf("digestID %d not in MSO", item.DigestID)
		}

		// constant-time comparison — prevents timing side channel
		// where early exit on first mismatch would leak digest bytes
		if subtle.ConstantTimeCompare(hash[:], expectedDigest) != 1 {
			return nil, fmt.Errorf("digest mismatch for %s", item.ElementIdentifier)
		}

		attrs[item.ElementIdentifier] = item.ElementValue
	}
	return attrs, nil
}

// Verify performs full issuerAuth verification for a single known
// namespace: verifyIssuerAuthAndMSO's chain/signature/MSO/validity checks,
// followed by recomputing and comparing each disclosed item's digest in
// namespace.
//
// This does NOT check deviceAuth — use VerifyWithDeviceAuth for the full
// presentation flow. Kept separate so issuer-only verification (e.g. just
// checking the MSO/digests without a live session) still works standalone.
func (v *Verifier) Verify(mdoc *MDoc, namespace string) VerificationResult {
	mso, result := v.verifyIssuerAuthAndMSO(mdoc)
	if mso == nil {
		return result
	}

	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		result.Error = fmt.Sprintf("namespace %s not in MSO", namespace)
		return result
	}

	attrs, err := verifyNamespaceDigests(mdoc.IssuerSigned.NameSpaces[namespace], nsDigests)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Attributes = attrs
	result.Valid = true
	return result
}

// VerifyAllDisclosedNamespaces is Verify's issuance-time counterpart: rather
// than checking a single caller-supplied namespace, it verifies digests for
// every namespace actually present in mdoc.IssuerSigned.NameSpaces. Needed
// because at issuance the caller doesn't know the docType's namespace set
// ahead of a single Verify(mdoc, namespace) call, unlike presentation (which
// already knows the namespace from the DCQL claim path being disclosed).
// Returns the decoded namespace -> elementIdentifier -> value map alongside
// the same VerificationResult shape Verify returns (Attributes is left at
// its zero value here — namespace-scoped attributes are the return map, not
// the result, since a single flat map would lose the namespace boundary).
func (v *Verifier) VerifyAllDisclosedNamespaces(mdoc *MDoc) (map[string]map[string]any, VerificationResult) {
	mso, result := v.verifyIssuerAuthAndMSO(mdoc)
	if mso == nil {
		return nil, result
	}

	resolved := make(map[string]map[string]any, len(mdoc.IssuerSigned.NameSpaces))
	for namespace, items := range mdoc.IssuerSigned.NameSpaces {
		nsDigests, ok := mso.ValueDigests[namespace]
		if !ok {
			result.Error = fmt.Sprintf("namespace %s not in MSO", namespace)
			return nil, result
		}
		attrs, err := verifyNamespaceDigests(items, nsDigests)
		if err != nil {
			result.Error = err.Error()
			return nil, result
		}
		resolved[namespace] = attrs
	}

	result.Attributes = nil
	result.Valid = true
	return resolved, result
}

// VerifyWithDeviceAuth performs the same checks as Verify, and additionally
// validates deviceAuth against the deviceKey embedded in the (now-trusted)
// MSO, using the SAME session transcript the verifier itself generated.
//
// Device binding is one of the main anti-cloning and anti-replay protections
// in 18013-5, and it is the reason to prefer this over Verify: Verify never
// touches deviceAuth or deviceKeyInfo, so a cloned mdoc — issuerSigned copied
// to another device — passes it.
func (v *Verifier) VerifyWithDeviceAuth(mdoc *MDoc, namespace string, docType string, transcript SessionTranscript, deviceAuthBytes []byte) VerificationResult {
	result := v.Verify(mdoc, namespace)
	if !result.Valid {
		return result
	}

	// The docType the verifier asked for must be the one the issuer signed.
	// Verify() has already established that result.DocType is MSO.docType, so
	// this compares against the signed value rather than the envelope. Without
	// it a caller-supplied docType would still be caught — the reconstructed
	// DeviceAuthentication payload below would not match the signature — but
	// only as an opaque "deviceAuth signature invalid".
	if docType != result.DocType {
		result.Valid = false
		result.Error = fmt.Sprintf(
			"docType mismatch: verifier requested %q but the signed MSO says %q",
			docType, result.DocType,
		)
		return result
	}

	// Re-decode the MSO to get deviceKeyInfo. Verify() already proved
	// msg.Payload is authentic (signature + chain checked), so this is safe.
	msg, err := decodeCoseSign1(mdoc.IssuerSigned.IssuerAuth)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decode cose (deviceAuth phase): %v", err)
		return result
	}
	mso, err := tag24Unwrap[MSO](msg.Payload)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decode mso (deviceAuth phase): %v", err)
		return result
	}

	devicePub, err := ecdsaPublicKeyFromCOSE(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("reconstruct deviceKey: %v", err)
		return result
	}

	// Decode the deviceAuth COSE_Sign1. Its transmitted Payload is nil —
	// SignDeviceAuth detaches it before returning, matching the AV
	// Blueprint spec's own example (deviceSignature payload: null).
	deviceMsg, err := decodeCoseSign1(deviceAuthBytes)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decode deviceAuth cose: %v", err)
		return result
	}

	// Rebuild the DeviceAuthentication payload the holder signed. Two of its four
	// elements come from deliberately different places:
	//
	//   - SessionTranscript is the verifier's OWN. The verifier is the authority on
	//     the session, so substituting its own copy is what defeats replay: a
	//     signature produced over a different transcript (a different session, or
	//     replayed from elsewhere) hashes differently and fails below. Since the
	//     transmitted COSE_Sign1 has a detached (null) payload, this reconstruction
	//     is the only source of the bytes fed into Sig_structure, which collapses
	//     "content matches" and "signature valid" into a single check.
	//
	//   - DeviceNameSpaces are the RECEIVED bytes. ISO 18013-5 transmits
	//     DeviceNameSpacesBytes at deviceSigned.nameSpaces precisely so a verifier
	//     can rebuild this structure, and taking them from the wire is not a
	//     relaxation — the signature covers them, so substituted bytes can only
	//     make a valid signature fail. Reconstructing tag24(empty map) here
	//     instead conflated the two cases above: a conformant holder that encoded
	//     its empty map any other way (indefinite-length, say) was rejected with
	//     "signature invalid", which was not what had gone wrong, and the received
	//     field was left neither verified nor rejected.
	//
	// Whether any device-signed namespaces are ACCEPTABLE is a separate question,
	// answered by the profile check after the signature has been verified.
	deviceNameSpaces, err := deviceNameSpacesForVerification(mdoc)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	// Decode now only to establish that the payload being signed over is
	// well-formed; its contents are judged after verification, since a rule
	// enforced on unauthenticated bytes proves nothing about the holder.
	deviceNameSpaceMap, err := decodeDeviceNameSpaces(deviceNameSpaces)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("malformed deviceSigned.nameSpaces: %v", err)
		return result
	}

	expectedDeviceAuth := DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           result.DocType, // the signed value; equal to docType by the check above
		DeviceNameSpaces:  deviceNameSpaces,
	}
	expectedPayload, err := tag24Wrap(expectedDeviceAuth)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("wrap expected deviceAuthentication: %v", err)
		return result
	}
	deviceMsg.Payload = expectedPayload

	deviceVerifier, err := cose.NewVerifier(cose.AlgorithmES256, devicePub)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("create device verifier: %v", err)
		return result
	}
	if err := deviceMsg.Verify(nil, deviceVerifier); err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("deviceAuth signature invalid: %v", err)
		return result
	}

	// Profile check, on authenticated content. Data in DeviceSigned is
	// self-asserted by the holder rather than attested by the issuer, and the AV
	// Blueprint profile has no holder-asserted claims, so any namespace here is
	// outside what this verifier is prepared to interpret. Rejecting is the
	// conservative choice: accepting would mean carrying claims the issuer never
	// signed, and callers read VerificationResult.Attributes without being able to
	// tell the two apart. A profile that does want them would surface them in a
	// field of their own instead of relaxing this.
	//
	// DeviceAuthValid stays false even though the signature verified, so a caller
	// that reads it without checking Valid cannot mistake this for acceptance.
	if len(deviceNameSpaceMap) != 0 {
		namespaces := make([]string, 0, len(deviceNameSpaceMap))
		for ns := range deviceNameSpaceMap {
			namespaces = append(namespaces, ns)
		}
		slices.Sort(namespaces)
		result.Valid = false
		result.Error = fmt.Sprintf(
			"device-signed namespaces are not permitted in this profile: the deviceAuth "+
				"signature is valid, but the document asserts %d holder-signed namespace(s) %v, "+
				"which carry no issuer attestation",
			len(namespaces), namespaces,
		)
		return result
	}

	result.DeviceAuthValid = true
	return result
}

// deviceNameSpacesForVerification returns the DeviceNameSpacesBytes to rebuild
// DeviceAuthentication with — the transmitted bytes whenever there is a
// DeviceSigned envelope to take them from.
//
// The fallback covers VerifyWithDeviceAuth's other call shape, where deviceAuth
// arrives as a parameter and no DeviceResponse has been assembled yet (the demo
// and this package's tests call Issue/SelectiveDisclose/SignDeviceAuth directly).
// There is nothing on the wire to read in that case, and the only thing a holder
// in this profile signs is the empty map, so assume it: a wrong assumption is
// caught by the signature check either way.
func deviceNameSpacesForVerification(mdoc *MDoc) (cbor.RawMessage, error) {
	if mdoc.DeviceSigned != nil {
		if len(mdoc.DeviceSigned.NameSpaces) == 0 {
			return nil, fmt.Errorf("deviceSigned is present but carries no nameSpaces")
		}
		return mdoc.DeviceSigned.NameSpaces, nil
	}

	empty, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("encode empty nameSpaces: %w", err)
	}
	return cbor.RawMessage(empty), nil
}

// decodeDeviceNameSpaces validates that raw really is
// `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)` and returns the
// namespaces it wraps, their contents left undecoded.
//
// The emptiness of the result is what the profile check tests, rather than a byte
// comparison against tag24Wrap(map[string]any{}): CBOR admits more than one
// encoding of an empty map, and comparing bytes would reject a conformant holder
// for choosing a different one — the very brittleness this replaced.
func decodeDeviceNameSpaces(raw cbor.RawMessage) (map[string]cbor.RawMessage, error) {
	var rawTag cbor.RawTag
	if err := cbor.Unmarshal(raw, &rawTag); err != nil {
		return nil, fmt.Errorf("not tag-24 embedded CBOR: %w", err)
	}
	if rawTag.Number != 24 {
		return nil, fmt.Errorf("has CBOR tag %d, want 24", rawTag.Number)
	}
	var inner []byte
	if err := cbor.Unmarshal(rawTag.Content, &inner); err != nil {
		return nil, fmt.Errorf("tag 24 does not wrap a byte string: %w", err)
	}
	var namespaces map[string]cbor.RawMessage
	if err := cbor.Unmarshal(inner, &namespaces); err != nil {
		return nil, fmt.Errorf("embedded DeviceNameSpaces is not a map: %w", err)
	}
	return namespaces, nil
}

// VerifyDeviceResponse verifies every document in a DeviceResponse via
// VerifyWithDeviceAuth, extracting deviceAuth from each document's
// DeviceSigned field instead of requiring it as a separate parameter —
// this is the entry point a verifier that actually received a
// DeviceResponse (rather than calling Issue/SelectiveDisclose directly,
// as the tests/demo do) would use.
func (v *Verifier) VerifyDeviceResponse(resp DeviceResponse, namespace string, docType string, transcript SessionTranscript) ([]VerificationResult, error) {
	results := make([]VerificationResult, 0, len(resp.Documents))
	for i := range resp.Documents {
		doc := resp.Documents[i]
		if doc.DeviceSigned == nil {
			return nil, fmt.Errorf("document %d: missing deviceSigned", i)
		}
		deviceAuthBytes := []byte(doc.DeviceSigned.DeviceAuth.DeviceSignature)
		results = append(results, v.VerifyWithDeviceAuth(&doc, namespace, docType, transcript, deviceAuthBytes))
	}
	return results, nil
}
