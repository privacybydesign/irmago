package mdoc

import (
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
}

// Verify performs full issuerAuth verification:
//  1. Decode COSE_Sign1
//  2. Extract x5chain from header 33
//  3. Walk the cert chain: DS cert → IACA cert → trusted root
//  4. Verify COSE_Sign1 signature using DS cert's public key
//  5. Decode MSO from payload
//  6. For each disclosed item: recompute digest and compare (constant-time)
//
// This does NOT check deviceAuth — use VerifyWithDeviceAuth for the full
// presentation flow. Kept separate so issuer-only verification (e.g. just
// checking the MSO/digests without a live session) still works standalone.
func (v *Verifier) Verify(mdoc *MDoc, namespace string) VerificationResult {
	fmt.Println("\n--- VERIFIER: Verifying mDoc ---")

	result := VerificationResult{
		DocType:    mdoc.DocType,
		Attributes: make(map[string]any),
	}

	// Step 1: decode COSE_Sign1
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &msg); err != nil {
		result.Error = fmt.Sprintf("decode cose: %v", err)
		return result
	}

	// Step 2: extract x5chain from unprotected header 33
	// x5chain = [DS cert DER, IACA cert DER]
	// go-cose decodes [][]byte as []any where each element is []byte
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		result.Error = "no x5chain in issuerAuth header 33"
		return result
	}

	chainRaw, ok := rawVal.([]any)
	if !ok {
		// fallback: single cert
		single, ok2 := rawVal.([]byte)
		if !ok2 {
			result.Error = fmt.Sprintf("x5chain wrong type: %T", rawVal)
			return result
		}
		chainRaw = []any{single}
	}

	if len(chainRaw) == 0 {
		result.Error = "x5chain is empty"
		return result
	}

	// parse all certs: certs[0] = DS cert (leaf), certs[1..] = intermediates (IACA cert)
	certs := make([]*x509.Certificate, 0, len(chainRaw))
	for i, raw := range chainRaw {
		b, ok := raw.([]byte)
		if !ok {
			result.Error = fmt.Sprintf("x5chain[%d] wrong type: %T", i, raw)
			return result
		}
		c, err := x509.ParseCertificate(b)
		if err != nil {
			result.Error = fmt.Sprintf("parse x5chain[%d]: %v", i, err)
			return result
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
		return result
	}
	fmt.Printf("  Certificate chain: valid ✓  (depth %d: %s → %s)\n",
		len(certs),
		dsCert.Subject.CommonName,
		certs[len(certs)-1].Subject.CommonName,
	)

	// Step 4: verify COSE_Sign1 signature using DS cert's public key
	// go-cose internally builds the Sig_structure and verifies ECDSA against it
	// NOT the bare MSO bytes — the Sig_structure wrapping is what actually gets signed
	coseverifier, err := cose.NewVerifier(cose.AlgorithmES256, dsCert.PublicKey)
	if err != nil {
		result.Error = fmt.Sprintf("create verifier: %v", err)
		return result
	}
	if err := msg.Verify(nil, coseverifier); err != nil {
		result.Error = fmt.Sprintf("MSO signature invalid: %v", err)
		return result
	}
	fmt.Println("  MSO signature: valid ✓")

	// Step 5: decode MSO from payload
	var mso MSO
	if err := cbor.Unmarshal(msg.Payload, &mso); err != nil {
		result.Error = fmt.Sprintf("decode mso: %v", err)
		return result
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
		return result
	}
	if now.After(mso.ValidityInfo.ValidUntil) {
		result.Error = fmt.Sprintf("credential expired: validUntil=%s, now=%s",
			mso.ValidityInfo.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
		return result
	}
	fmt.Println("  MSO validityInfo: within window ✓")

	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		result.Error = fmt.Sprintf("namespace %s not in MSO", namespace)
		return result
	}

	// Step 6: verify each disclosed item's digest
	// Recompute SHA-256(Tag24(item)) and compare against MSO.ValueDigests[digestID]
	for _, tag24item := range mdoc.IssuerSigned.NameSpaces[namespace] {
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			result.Error = fmt.Sprintf("unwrap tag24: %v", err)
			return result
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			result.Error = fmt.Sprintf("unwrap inner: %v", err)
			return result
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			result.Error = fmt.Sprintf("decode item: %v", err)
			return result
		}

		hash := sha256.Sum256(tag24item.EncodedItem)
		expectedDigest, exists := nsDigests[item.DigestID]
		if !exists {
			result.Error = fmt.Sprintf("digestID %d not in MSO", item.DigestID)
			return result
		}

		// constant-time comparison — prevents timing side channel
		// where early exit on first mismatch would leak digest bytes
		if subtle.ConstantTimeCompare(hash[:], expectedDigest) != 1 {
			result.Error = fmt.Sprintf("digest mismatch for %s", item.ElementIdentifier)
			return result
		}

		fmt.Printf("  %s = %v  digest: ✓\n", item.ElementIdentifier, item.ElementValue)
		result.Attributes[item.ElementIdentifier] = item.ElementValue
	}

	// stash decoded MSO on the result path isn't exposed publicly, so
	// VerifyWithDeviceAuth re-derives what it needs (deviceKey) itself.
	result.Valid = true
	fmt.Println("  Verification: PASSED ✓")
	return result
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
	var mso MSO
	if err := cbor.Unmarshal(msg.Payload, &mso); err != nil {
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
	expectedPayload, err := cbor.Marshal(expectedDeviceAuth)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("marshal expected deviceAuthentication: %v", err)
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

	fmt.Println("  deviceAuth signature: valid ✓  (matches session transcript)")
	result.DeviceAuthValid = true
	return result
}
