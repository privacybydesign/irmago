package mdoc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// VERIFIER
// ============================================================

// Verifier holds the pre-installed trust anchor (IACA root cert)
// Phase 1: our own test self-signed IACA root
// Phase 2: Yivi's own IACA root, manually distributed to verifiers
// Phase 3: EU AV Blueprint root CA (from official AP trust list)
type Verifier struct {
	trustedRoots *x509.CertPool

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
	return &Verifier{trustedRoots: pool}
}

// NewVerifierFromPool is like NewVerifier but takes an already-built trust-
// root pool directly, so callers that already maintain a *x509.CertPool
// (e.g. the wallet's own trust model) don't need to keep a parallel
// []*x509.Certificate list just to construct a Verifier.
func NewVerifierFromPool(rootCerts *x509.CertPool) *Verifier {
	return &Verifier{trustedRoots: rootCerts}
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
	DeviceAuthValid bool // FIX: now actually populated — see VerifyWithDeviceAuth

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
	result := VerificationResult{
		DocType:    mdoc.DocType,
		Attributes: make(map[string]any),
	}

	// Step 1: decode COSE_Sign1
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &msg); err != nil {
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
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Step 3: verify the full chain
	// x509.Verify walks: DS cert → intermediates → trusted root
	// This is what prevents a chain attack — attacker's root won't be in trustedRoots
	_, err := dsCert.Verify(x509.VerifyOptions{
		Roots:         v.trustedRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   v.currentTime(),
	})
	if err != nil {
		result.Error = fmt.Sprintf("chain verification failed: %v", err)
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

	result.ValidityInfo = mso.ValidityInfo

	// Best-effort: reconstruct the device public key embedded in the MSO.
	// Left nil on failure rather than failing verification outright — see
	// VerificationResult.DeviceKey's doc comment.
	if devicePub, err := ecdsaPublicKeyFromCOSE(mso.DeviceKeyInfo.DeviceKey); err == nil {
		result.DeviceKey = devicePub
	}

	return &mso, result
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
// FIX: this closes the gap explicitly called out in the original comment
// ("deviceAuth verification not yet implemented"). Device binding is one
// of the main anti-cloning/anti-replay protections in 18013-5 — without
// checking it, a cloned mdoc (issuerSigned copied to another device) would
// still verify successfully, since Verify() never touches deviceAuth or
// deviceKeyInfo at all.
func (v *Verifier) VerifyWithDeviceAuth(mdoc *MDoc, namespace string, docType string, transcript SessionTranscript, deviceAuthBytes []byte) VerificationResult {
	result := v.Verify(mdoc, namespace)
	if !result.Valid {
		return result
	}

	// Re-decode the MSO to get deviceKeyInfo. Verify() already proved
	// msg.Payload is authentic (signature + chain checked), so this is safe.
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &msg); err != nil {
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
	var deviceMsg cose.Sign1Message
	if err := cbor.Unmarshal(deviceAuthBytes, &deviceMsg); err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decode deviceAuth cose: %v", err)
		return result
	}

	// Rebuild the DeviceAuthentication payload using the verifier's OWN
	// session transcript — since the wire message carries no payload,
	// this reconstruction is now the ONLY source of the bytes fed into
	// Sig_structure for verification below. If a signature was produced
	// over a different transcript (a different session, or replayed from
	// elsewhere), the hash won't match and Verify() will fail outright —
	// there's no separate "payload matches" check needed anymore, since
	// supplying the payload ourselves and verifying against it collapses
	// both checks (content + signature) into one.
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("encode empty nameSpaces: %v", err)
		return result
	}
	expectedDeviceAuth := DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           docType,
		DeviceNameSpaces:  emptyNS,
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

	result.DeviceAuthValid = true
	return result
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
