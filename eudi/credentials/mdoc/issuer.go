package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	cose "github.com/veraison/go-cose"
)

// ============================================================
// ISSUER
// ============================================================

const (
	// minSaltLength is the floor ISO/IEC 18013-5 puts on an IssuerSignedItem's
	// random value: at least 16 bytes.
	minSaltLength = 16

	// saltLength is what this issuer actually generates. At the floor rather than
	// above it because nothing here needs the extra bytes, and every byte is
	// carried by every disclosed item on every presentation.
	saltLength = 16
)

// Editing saltLength below the ISO floor fails the build: the subtraction is a
// negative constant, which does not convert to uint. The runtime check in Issue
// still stands, for a salt whose length is ever decided at runtime rather than
// by this constant.
const _ = uint(saltLength - minSaltLength)

// Issuer holds a two-level certificate chain:
//
//	IACA root CA (offline, self-signed, signs DS certs only)
//	    └── DS cert (online HSM, signs every MSO)
//
// In production:
//   - iacakey lives in an offline/vaulted HSM — used once a year to sign new DS certs
//   - dskey lives in an online HSM — used for every credential issuance
//   - Phase 3: iacacert itself is signed by the EU AV Blueprint root CA
type Issuer struct {
	iacakey  *ecdsa.PrivateKey
	iacacert *x509.Certificate

	dskey  *ecdsa.PrivateKey
	dscert *x509.Certificate
}

func NewIssuer() (*Issuer, error) {
	// ── Step 1: IACA root CA (self-signed) ──────────────────────
	// In production: key generated in offline HSM key ceremony, never extracted
	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate IACA key: %w", err)
	}

	iacaSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	iacaTemplate := &x509.Certificate{
		SerialNumber: iacaSerial,
		Subject: pkix.Name{
			CommonName:   "Test Age Verification IACA Root CA",
			Organization: []string{"Yivi Test"},
		},
		// NotBefore is backdated 5 minutes: real CAs do this to absorb clock
		// skew between issuer/verifier clocks, as per common practice in
		// CA/Browser Forum baseline requirements and general X.509 issuance
		// guidance — not something the AV Blueprint or ISO 18013-5 mandates
		// itself. It also means the cert's own validity window starts
		// meaningfully before the MSO's validFrom (set later, in Issue()) —
		// giving tests a real, deterministic gap to check the MSO
		// validityInfo check independently of cert expiry.
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true, // can sign other certs
		MaxPathLen:            1,    // only one level below allowed (DS cert)
	}

	// self-signed: parent == template
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("create IACA cert: %w", err)
	}
	iacaCert, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		return nil, fmt.Errorf("parse IACA cert: %w", err)
	}

	// ── Step 2: DS cert (signed by IACA root) ───────────────────
	// In production: key generated in online HSM, only public key goes to IACA for signing
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DS key: %w", err)
	}

	dsSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	dsTemplate := &x509.Certificate{
		SerialNumber: dsSerial,
		Subject: pkix.Name{
			CommonName:   "Test Age Verification DS - 001",
			Organization: []string{"Yivi Test"},
		},
		// Backdated 5 minutes — see IACA NotBefore comment above.
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false, // leaf cert — cannot sign other certs
		// ISO 18013-5 Annex B.1.2 requires the mdoc Document Signer extended
		// key usage on a DS certificate, and the verifier now enforces it (see
		// checkDocumentSignerEKU). crypto/x509 has no enum member for the OID,
		// so it goes in UnknownExtKeyUsage — CreateCertificate encodes both
		// that and ExtKeyUsage into the one EKU extension.
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{isoMdocDocumentSignerEKU},
	}

	// parent = iacaCert (parsed), signed with iacaKey — this establishes the chain
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("create DS cert: %w", err)
	}
	dsCert, err := x509.ParseCertificate(dsDER)
	if err != nil {
		return nil, fmt.Errorf("parse DS cert: %w", err)
	}

	return &Issuer{
		iacakey:  iacaKey,
		iacacert: iacaCert,
		dskey:    dsKey,
		dscert:   dsCert,
	}, nil
}

// IACACert returns the issuer's IACA root certificate — the trust anchor
// verifiers should pre-install (e.g. via NewVerifier). Never the private key.
func (iss *Issuer) IACACert() *x509.Certificate {
	return iss.iacacert
}

// DSCert returns the issuer's DS certificate. Informational only — it
// already travels with every issued mDoc via x5chain, so verifiers never
// need to call this themselves.
func (iss *Issuer) DSCert() *x509.Certificate {
	return iss.dscert
}

// shuffleIdentifiers randomizes identifiers in place using a
// cryptographically secure Fisher-Yates shuffle. See the comment in
// Issue() for why this must be random rather than sorted.
func shuffleIdentifiers(identifiers []string) error {
	for i := len(identifiers) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("generate shuffle index: %w", err)
		}
		j := int(jBig.Int64())
		identifiers[i], identifiers[j] = identifiers[j], identifiers[i]
	}
	return nil
}

// Issue builds and signs an mDoc for the given claims
// holderPub is the holder's device public key — gets embedded in MSO.deviceKeyInfo
// This locks the credential to the specific device that generated that key pair
func (iss *Issuer) Issue(docType string, namespace string, claims map[string]any, holderPub *ecdsa.PublicKey) (*MDoc, error) {
	// ── Build IssuerSignedItems ──────────────────────────────────
	// Claim order is randomized — deliberately NOT sorted — before
	// digestID assignment. A deterministic order (e.g. alphabetical, which
	// an earlier version of this code used) lets a verifier infer the
	// relative order of UNDISCLOSED claims from a disclosed one's
	// digestID: for a small, guessable vocabulary like this profile's
	// age_over_NN thresholds, "digestID 1 = age_over_18 out of 3 total"
	// reveals there's one undisclosed claim below 18 and one above it,
	// even though neither was ever disclosed. A fresh cryptographically
	// random permutation per issuance removes that correlation entirely.
	// Multipaz's MdocUtil.generateIssuerNameSpaces shuffles digest IDs for
	// this exact same reason.
	identifiers := make([]string, 0, len(claims))
	for identifier := range claims {
		identifiers = append(identifiers, identifier)
	}
	if err := shuffleIdentifiers(identifiers); err != nil {
		return nil, fmt.Errorf("shuffle claim order: %w", err)
	}

	var items []IssuerSignedItem
	digestID := uint64(0)

	for _, identifier := range identifiers {
		value := claims[identifier]
		// A fresh random salt per item, without which the digest would be
		// brute-forceable: SHA-256(true) is always the same, so a verifier holding
		// the digest of an undisclosed boolean could simply hash both values and
		// see which matches. That is not hypothetical for this profile, whose
		// claims are all booleans.
		salt := make([]byte, saltLength)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		// Belt and braces against saltLength ever being edited down: the length is
		// a security parameter rather than a formatting choice, and a shortened
		// salt would leave every signature and digest still verifying, so nothing
		// downstream would notice.
		if len(salt) < minSaltLength {
			return nil, fmt.Errorf(
				"salt is %d bytes, but ISO/IEC 18013-5 requires the IssuerSignedItem random value to be at least %d",
				len(salt), minSaltLength)
		}
		item := IssuerSignedItem{
			DigestID:          digestID,
			Random:            salt,
			ElementIdentifier: identifier,
			ElementValue:      value,
		}
		items = append(items, item)
		digestID++
	}

	// ── Compute valueDigests ─────────────────────────────────────
	// Each digest = SHA-256(Tag24(CBOR(IssuerSignedItem)))
	// These go into the MSO — signed by the DS key — binding values to the credential
	valueDigests := make(map[uint64][]byte)
	for _, item := range items {
		digest, err := hashTag24Item(item)
		if err != nil {
			return nil, fmt.Errorf("hash item: %w", err)
		}
		valueDigests[item.DigestID] = digest
	}

	// ── Embed holder's device public key into MSO ────────────────
	deviceKey, err := coseKeyFromECDSA(holderPub)
	if err != nil {
		return nil, fmt.Errorf("convert holder pub key: %w", err)
	}

	// ── Build MSO ────────────────────────────────────────────────
	//
	// The validity timestamps are coarsened to midnight UTC rather than stamped
	// with the wallclock. Proof-of-age attestations are single-use and issued in
	// batches precisely so a holder cannot be followed between relying parties,
	// and a per-second timestamp defeats that on its own: every attestation in a
	// batch would carry a distinct validUntil, which is as good a correlator as
	// the credential it is trying to protect. The AV profile therefore has the
	// provider "set timestamps in the ValidityInfo structure with a precision
	// that limits the linkability information, following the ISO/IEC 18013-5
	// recommendation by setting the hh, mm and ss information to the same value
	// on each Proof of Age Attestation" (Annex A). The EU reference issuer does
	// the same for batch credentials — see is_batch_credential in its
	// formatter_func.py, which replaces hour/minute/second with zero.
	//
	// Coarsening downwards also keeps validFrom in the past, so a credential is
	// never briefly not-yet-valid against a verifier whose clock trails ours.
	now := time.Now().UTC().Truncate(24 * time.Hour)
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{namespace: valueDigests},
		DocType:         docType,
		ValidityInfo: ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		DeviceKeyInfo: DeviceKeyInfo{DeviceKey: deviceKey},
	}

	// MSO travels as Tag24(CBOR(MSO)) inside issuerAuth's payload — per ISO
	// 18013-5's MobileSecurityObjectBytes = #6.24(bstr .cbor
	// MobileSecurityObject), and directly confirmed by the AV Blueprint's
	// own worked example (Annex A §A.11 shows "24(<<{...}>>)" for the MSO
	// payload, not a bare map).
	msoBytes, err := tag24WrapWithMode(mso, avTimeEncMode)
	if err != nil {
		return nil, fmt.Errorf("wrap mso: %w", err)
	}

	// ── Sign MSO with DS key (NOT IACA key) ──────────────────────
	// COSE_Sign1 structure: [protected, unprotected, payload, signature]
	// protected:    {alg: -7} = ES256 — included in signature, prevents algorithm swap
	// unprotected:  {33: [DS cert, IACA cert]} = x5chain — not in signature, just transport hint
	// payload:      MSO bytes
	// signature:    ECDSA(dskey, SHA-256(Sig_structure))
	signer, err := cose.NewSigner(cose.AlgorithmES256, iss.dskey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// UntaggedSign1Message, not Sign1Message: ISO 18013-5's `IssuerAuth =
	// COSE_Sign1` is RFC 8152's bare four-element array, and go-cose's
	// Sign1Message marshals the COSE_Sign1_Tagged form instead (prefixing tag
	// 18, 0xd2). The tag sits outside Sig_structure, so this changes only the
	// envelope, never the signature.
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers,
		Payload: msoBytes}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)

	// x5chain header 33: [DS cert DER, IACA cert DER]
	// EU root NOT included — verifier has it pre-installed in their trust store
	// DS cert = leaf (verifier uses its public key to verify MSO signature)
	// IACA cert = intermediate (verifier uses it to verify DS cert)
	chain := [][]byte{
		iss.dscert.Raw,   // leaf
		iss.iacacert.Raw, // intermediate
	}
	msg.Headers.Unprotected[int64(33)] = chain

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign mso: %w", err)
	}

	coseBytes, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal cose: %w", err)
	}

	// ── Tag-24 wrap each item for NameSpaces ─────────────────────
	tag24Items := make([]Tag24Item, len(items))
	for i, item := range items {
		wrapped, err := tag24Wrap(item)
		if err != nil {
			return nil, fmt.Errorf("wrap item: %w", err)
		}
		tag24Items[i] = Tag24Item{EncodedItem: wrapped}
	}

	return &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: tag24Items},
			IssuerAuth: coseBytes,
		},
	}, nil
}
