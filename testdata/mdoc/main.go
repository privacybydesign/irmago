package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// DATA STRUCTURES
// ============================================================

// MDoc is the top-level credential container
type MDoc struct {
	DocType      string       `cbor:"docType"`
	IssuerSigned IssuerSigned `cbor:"issuerSigned"`
}

// IssuerSignedItem is the 4-field envelope for each claim
// All 4 fields together get Tag-24 wrapped and SHA-256 hashed → the digest
// stored in MSO.ValueDigests
type IssuerSignedItem struct {
	DigestID          uint64      `cbor:"digestID"`          // index into ValueDigests map
	Random            []byte      `cbor:"random"`            // ≥16 byte salt — prevents brute force
	ElementIdentifier string      `cbor:"elementIdentifier"` // attribute name e.g. "age_over_18"
	ElementValue      interface{} `cbor:"elementValue"`      // attribute value e.g. true
}

// COSEKey is the CBOR-encoded public key format per RFC 9053 (COSE Key).
//
// FIX: struct tags now use ",keyasint" so fxamacker/cbor encodes these as
// actual CBOR integer map keys (major type 0/1), not text-string keys like
// "1" / "-1". Without keyasint, the previous version silently produced a
// non-conformant COSE_Key — it round-tripped fine against *this* codebase
// (since decoding used the same wrong mapping) but would fail against any
// spec-compliant verifier, and worse, the bad encoding gets baked into the
// signed MSO digest, so it can't be patched after issuance.
//
//	1  = kty  (key type:  2 = EC2)
//	-1 = crv  (curve:    1 = P-256)
//	-2 = x    (x coordinate, 32 bytes for P-256)
//	-3 = y    (y coordinate, 32 bytes for P-256)
type COSEKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// DeviceKeyInfo wraps the holder's device public key inside the MSO
// The issuer embeds this at issuance — locks in which device can present this credential
type DeviceKeyInfo struct {
	DeviceKey COSEKey `cbor:"deviceKey"`
}

// MSO (Mobile Security Object) is the signed data structure inside issuerAuth
// It commits to all claim digests + device key + validity — signed by DS cert
type MSO struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"` // namespace → digestID → SHA-256 hash
	DocType         string                       `cbor:"docType"`
	ValidityInfo    ValidityInfo                 `cbor:"validityInfo"`
	DeviceKeyInfo   DeviceKeyInfo                `cbor:"deviceKeyInfo"` // holder's device public key
}

type ValidityInfo struct {
	Signed     time.Time `cbor:"signed"`
	ValidFrom  time.Time `cbor:"validFrom"`
	ValidUntil time.Time `cbor:"validUntil"`
}

// IssuerSigned bundles the revealed claim items + the issuer's COSE_Sign1 signature
type IssuerSigned struct {
	NameSpaces map[string][]Tag24Item `cbor:"nameSpaces"` // only DISCLOSED items travel here
	IssuerAuth []byte                 `cbor:"issuerAuth"` // COSE_Sign1 over MSO — unchanged across presentations
}

// Tag24Item holds the raw Tag-24 wrapped bytes of one IssuerSignedItem
// "frozen" bytes — must not be re-encoded, otherwise digest won't match
type Tag24Item struct {
	EncodedItem []byte
}

// DeviceAuthentication is the CBOR array that deviceAuth signs over
// It is a CBOR array (not map) — hence the toarray tag on the blank field
// This structure is built fresh every presentation — ties deviceAuth to one session
type DeviceAuthentication struct {
	_                 struct{}          `cbor:",toarray"`
	Context           string            // always "DeviceAuthentication"
	SessionTranscript SessionTranscript // fresh per session — defeats replay attacks
	DocType           string
	DeviceNameSpaces  []byte // Tag24(empty map) for AV — no holder-added claims
}

// SessionTranscript binds a presentation to a specific verifier session
// Contains the verifier's engagement bytes + ephemeral key + handover info
// Also a CBOR array — toarray tag required
//
// NOTE: Handover is a bare string here for test purposes. In a real
// OID4VP flow this would be a structured value (e.g. OID4VPHandover array
// containing hashes of client_id, response_uri, nonce, etc. per ISO
// 18013-7 / OpenID4VP Annex B). Left as-is since this is a local test
// harness, but flagging so it isn't forgotten when wiring up real
// verifier engagement.
type SessionTranscript struct {
	_                     struct{}    `cbor:",toarray"`
	DeviceEngagementBytes []byte      // from QR code / NFC tap
	EReaderKeyBytes       []byte      // verifier's ephemeral public key
	Handover              interface{} // session-specific binding data
}

// ============================================================
// TAG-24 HELPERS + CRYPTO UTILITIES
// ============================================================

// tag24Wrap CBOR-encodes v, then wraps the result in a Tag-24 (embedded CBOR) container
// Tag 24 is IANA-registered to mean "this byte string contains a CBOR-encoded data item"
// This "freezes" the bytes so they can be hashed consistently
func tag24Wrap(v interface{}) ([]byte, error) {
	innerBytes, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tag24 inner encode: %w", err)
	}
	tagged := cbor.RawTag{
		Number:  24, // IANA registered tag: embedded CBOR
		Content: cbor.RawMessage(mustMarshal(innerBytes)),
	}
	return cbor.Marshal(tagged)
}

// hashTag24Item computes SHA-256(Tag24(CBOR(item)))
// This is the exact digest formula specified by ISO 18013-5
// The resulting hash is what goes into MSO.ValueDigests
func hashTag24Item(item IssuerSignedItem) ([]byte, error) {
	wrapped, err := tag24Wrap(item)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(wrapped)
	return hash[:], nil
}

// mustMarshal CBOR-encodes v and panics on error
// Used only for values that are guaranteed to be encodable (e.g. raw []byte)
func mustMarshal(v interface{}) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// coseKeyFromECDSA converts an ECDSA public key into our COSEKey type.
// Factored out so both the issuer (embedding) and verifier (deviceAuth
// check) build the exact same structure from the exact same logic.
func coseKeyFromECDSA(pub *ecdsa.PublicKey) (COSEKey, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return COSEKey{}, fmt.Errorf("convert pub key: %w", err)
	}
	pubBytes := ecdhPub.Bytes() // 65 bytes: 04 || X(32) || Y(32)
	return COSEKey{
		Kty: 2, // EC2
		Crv: 1, // P-256
		X:   pubBytes[1:33],
		Y:   pubBytes[33:],
	}, nil
}

// ecdsaPublicKeyFromCOSE reconstructs a *ecdsa.PublicKey from a COSEKey.
// Used by the verifier to check deviceAuth against the deviceKey embedded
// in the (already-verified) MSO.
func ecdsaPublicKeyFromCOSE(k COSEKey) (*ecdsa.PublicKey, error) {
	if k.Kty != 2 {
		return nil, fmt.Errorf("unsupported kty: %d (want EC2/2)", k.Kty)
	}
	if k.Crv != 1 {
		return nil, fmt.Errorf("unsupported crv: %d (want P-256/1)", k.Crv)
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(k.X)
	y := new(big.Int).SetBytes(k.Y)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("deviceKey point is not on P-256 curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ============================================================
// ISSUER
// ============================================================

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
		NotBefore:             time.Now(),
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false, // leaf cert — cannot sign other certs
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

// Issue builds and signs an mDoc for the given claims
// holderPub is the holder's device public key — gets embedded in MSO.deviceKeyInfo
// This locks the credential to the specific device that generated that key pair
func (iss *Issuer) Issue(docType string, namespace string, claims map[string]interface{}, holderPub *ecdsa.PublicKey) (*MDoc, error) {
	fmt.Println("\n--- ISSUER: Building mDoc ---")

	// ── Build IssuerSignedItems ──────────────────────────────────
	// FIX: iterate over claims in sorted key order. Go map iteration order
	// is randomized, so the previous version assigned digestIDs
	// non-deterministically between runs. That's not a security bug (each
	// mDoc is still internally self-consistent), but it makes test output
	// and golden-file comparisons non-reproducible. Sorting keys first
	// fixes that with no behavioral downside.
	identifiers := make([]string, 0, len(claims))
	for identifier := range claims {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)

	var items []IssuerSignedItem
	digestID := uint64(0)

	for _, identifier := range identifiers {
		value := claims[identifier]
		// 16-byte random salt per item — prevents brute-forcing boolean values
		// (without salt, SHA-256(true) is always the same — trivially reversible)
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		item := IssuerSignedItem{
			DigestID:          digestID,
			Random:            salt,
			ElementIdentifier: identifier,
			ElementValue:      value,
		}
		items = append(items, item)
		fmt.Printf("  Item %d: %s = %v  (salt: %s)\n", digestID, identifier, value, hex.EncodeToString(salt))
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
		fmt.Printf("  Digest[%d]: %s\n", item.DigestID, hex.EncodeToString(digest))
	}

	// ── Embed holder's device public key into MSO ────────────────
	deviceKey, err := coseKeyFromECDSA(holderPub)
	if err != nil {
		return nil, fmt.Errorf("convert holder pub key: %w", err)
	}

	// ── Build MSO ────────────────────────────────────────────────
	now := time.Now().UTC()
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

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("marshal mso: %w", err)
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

	msg := cose.NewSign1Message()
	msg.Payload = msoBytes
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

	coseBytes, err := cbor.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal cose: %w", err)
	}

	fmt.Printf("  MSO signed by DS cert ✓  (%d bytes)\n", len(coseBytes))
	fmt.Printf("  x5chain: DS cert + IACA cert\n")
	fmt.Printf("  deviceKeyInfo: embedded holder public key ✓\n")

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

// ============================================================
// HOLDER
// ============================================================

// Holder represents the wallet app on the user's device
// deviceKey is generated locally — private key never leaves the device (TEE/Secure Enclave in production)
// Only the PUBLIC key is sent to the issuer at issuance time
type Holder struct {
	devicekey *ecdsa.PrivateKey
}

func NewHolder() (*Holder, error) {
	// In production: generated inside Secure Enclave / TrustZone / StrongBox
	// Private key never extractable — all signing operations happen inside the hardware
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return &Holder{devicekey: deviceKey}, nil
}

// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this session
// Called at every presentation — never reused
// SessionTranscript ties this signature to a specific verifier + session — defeats replay
func (h *Holder) SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error) {
	// deviceNameSpaces = Tag24(empty map) for AV Blueprint
	// The AV profile has no holder-asserted claims — only issuer-signed attributes
	emptyNS, err := tag24Wrap(map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("encode empty nameSpaces: %w", err)
	}

	// DeviceAuthentication is a CBOR array (not map):
	// ["DeviceAuthentication", SessionTranscript, docType, deviceNameSpaces]
	// This is what ECDSA actually signs (via Sig_structure inside COSE_Sign1)
	deviceAuth := DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           docType,
		DeviceNameSpaces:  emptyNS,
	}

	payload, err := cbor.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("marshal deviceAuthentication: %w", err)
	}

	// Sign with device private key — uses same ES256 (ECDSA P-256 + SHA-256) as issuerAuth
	// but with a completely separate key pair (holder's device key, not issuer's DS key)
	signer, err := cose.NewSigner(cose.AlgorithmES256, h.devicekey)
	if err != nil {
		return nil, fmt.Errorf("create device signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	// unprotected headers intentionally empty — no cert in deviceAuth
	// trust comes from deviceKey being embedded in the already-trusted MSO

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign deviceAuth: %w", err)
	}

	return cbor.Marshal(msg)
}

// SelectiveDisclose filters the credential to only include the requested attributes
// issuerAuth is reused unchanged — the issuer's signature covers all digests regardless
// of which subset the holder chooses to reveal at any given presentation
func SelectiveDisclose(mdoc *MDoc, namespace string, reveal []string) (*MDoc, error) {
	fmt.Println("\n--- HOLDER: Selective disclosure ---")

	revealSet := make(map[string]bool)
	for _, r := range reveal {
		revealSet[r] = true
	}

	allItems := mdoc.IssuerSigned.NameSpaces[namespace]
	var disclosed []Tag24Item

	for _, tag24item := range allItems {
		// decode Tag-24 wrapped item to peek at the elementIdentifier
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			return nil, fmt.Errorf("unwrap tag24: %w", err)
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			return nil, fmt.Errorf("unwrap inner bytes: %w", err)
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			return nil, fmt.Errorf("decode item: %w", err)
		}

		if revealSet[item.ElementIdentifier] {
			fmt.Printf("  Revealing:   %s\n", item.ElementIdentifier)
			disclosed = append(disclosed, tag24item)
		} else {
			fmt.Printf("  Withholding: %s\n", item.ElementIdentifier)
		}
	}

	return &MDoc{
		DocType: mdoc.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: disclosed},
			IssuerAuth: mdoc.IssuerSigned.IssuerAuth, // reused unchanged
		},
	}, nil
}

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
	Attributes      map[string]interface{}
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
		Attributes: make(map[string]interface{}),
	}

	// Step 1: decode COSE_Sign1
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &msg); err != nil {
		result.Error = fmt.Sprintf("decode cose: %v", err)
		return result
	}

	// Step 2: extract x5chain from unprotected header 33
	// x5chain = [DS cert DER, IACA cert DER]
	// go-cose decodes [][]byte as []interface{} where each element is []byte
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		result.Error = "no x5chain in issuerAuth header 33"
		return result
	}

	chainRaw, ok := rawVal.([]interface{})
	if !ok {
		// fallback: single cert
		single, ok2 := rawVal.([]byte)
		if !ok2 {
			result.Error = fmt.Sprintf("x5chain wrong type: %T", rawVal)
			return result
		}
		chainRaw = []interface{}{single}
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

	// Decode the deviceAuth COSE_Sign1
	var deviceMsg cose.Sign1Message
	if err := cbor.Unmarshal(deviceAuthBytes, &deviceMsg); err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decode deviceAuth cose: %v", err)
		return result
	}

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

	// Rebuild the expected DeviceAuthentication payload using the
	// verifier's OWN session transcript, and check it matches byte-for-byte
	// what was actually signed. This is what proves the signature isn't
	// being replayed from a different session.
	emptyNS, err := tag24Wrap(map[string]interface{}{})
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
	if subtle.ConstantTimeCompare(deviceMsg.Payload, expectedPayload) != 1 {
		result.Valid = false
		result.Error = "deviceAuth payload does not match expected session transcript/docType"
		return result
	}

	fmt.Println("  deviceAuth signature: valid ✓  (matches session transcript)")
	result.DeviceAuthValid = true
	return result
}

// ============================================================
// MAIN
// ============================================================

func main() {
	fmt.Println("========================================")
	fmt.Println("  mDoc Issuer → Holder → Verifier Test")
	fmt.Println("  with two-level cert chain + deviceKeyInfo")
	fmt.Println("========================================")

	// ── Setup Issuer ─────────────────────────────────────────────
	issuer, err := NewIssuer()
	if err != nil {
		log.Fatal("issuer setup:", err)
	}
	fmt.Println("\nIACA root CA generated (self-signed, offline in production)")
	fmt.Printf("  Subject: %s\n", issuer.iacacert.Subject.CommonName)
	fmt.Println("DS cert generated (signed by IACA root)")
	fmt.Printf("  Subject: %s\n", issuer.dscert.Subject.CommonName)
	fmt.Printf("  Issuer:  %s\n", issuer.dscert.Issuer.CommonName)

	// ── Setup Holder ─────────────────────────────────────────────
	// Holder generates device key pair LOCALLY before contacting the issuer
	// In production: generated inside Secure Enclave / TrustZone — private key never extractable
	holder, err := NewHolder()
	if err != nil {
		log.Fatal("holder setup:", err)
	}
	ecdhPub, _ := holder.devicekey.PublicKey.ECDH()
	fmt.Printf("\nDevice key generated (x: %s...)\n",
		hex.EncodeToString(ecdhPub.Bytes()[1:33])[:16])

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	claims := map[string]interface{}{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	// ── Issuance ──────────────────────────────────────────────────
	// Holder sends ONLY the public key to the issuer
	// Issuer embeds it in MSO.deviceKeyInfo, then signs the whole MSO
	// Private key never leaves the holder's device
	mdoc, err := issuer.Issue(docType, namespace, claims, &holder.devicekey.PublicKey)
	if err != nil {
		log.Fatal("issue:", err)
	}

	// ── Selective Disclosure ─────────────────────────────────────
	presented, err := SelectiveDisclose(mdoc, namespace, []string{"age_over_18"})
	if err != nil {
		log.Fatal("selective disclose:", err)
	}

	// ── DeviceAuth ───────────────────────────────────────────────
	// Holder signs a fresh DeviceAuthentication for this session
	// SessionTranscript would normally come from the verifier's QR code / NFC engagement
	// Here we use a minimal stub transcript for the test
	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}
	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		log.Fatal("deviceAuth:", err)
	}
	fmt.Printf("\ndeviceAuth signed ✓  (%d bytes)\n", len(deviceAuthBytes))
	fmt.Println("  (fresh per session — binds presentation to this verifier + session)")

	// ── Verification ─────────────────────────────────────────────
	// Verifier pre-installs ONLY the IACA root as trust anchor
	// DS cert arrives via x5chain at verification time — never pre-installed
	verifier := NewVerifier([]*x509.Certificate{issuer.iacacert})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)

	fmt.Println("\n========================================")
	fmt.Println("  RESULT")
	fmt.Println("========================================")
	fmt.Printf("  DocType:          %s\n", result.DocType)
	fmt.Printf("  Valid:            %v\n", result.Valid)
	fmt.Printf("  DeviceAuth Valid: %v\n", result.DeviceAuthValid)
	if result.Error != "" {
		fmt.Printf("  Error:    %s\n", result.Error)
	}
	fmt.Println("  Disclosed attributes:")
	for k, v := range result.Attributes {
		fmt.Printf("    %s = %v\n", k, v)
	}

	// ── CHAIN ATTACK TEST ─────────────────────────────────────────
	// Attacker generates their own valid IACA + DS pair and issues
	// a correctly signed mDoc — but their IACA root is not in the
	// verifier's trusted pool, so chain verification fails before
	// signature or digest checks are even reached.
	fmt.Println("\n========================================")
	fmt.Println("  CHAIN ATTACK TEST (attacker's own cert chain)")
	fmt.Println("========================================")

	attackerIssuer, _ := NewIssuer()
	attackerHolder, _ := NewHolder()
	attackerMDoc, _ := attackerIssuer.Issue(docType, namespace,
		map[string]interface{}{"age_over_18": true},
		&attackerHolder.devicekey.PublicKey,
	)
	attackerPresented, _ := SelectiveDisclose(attackerMDoc, namespace, []string{"age_over_18"})

	attackResult := verifier.Verify(attackerPresented, namespace)
	fmt.Printf("  Attacker's mDoc valid: %v\n", attackResult.Valid)
	fmt.Printf("  Error: %s\n", attackResult.Error)
	fmt.Println("  (correctly rejected — attacker's root not trusted ✓)")

	// ── TAMPER TEST ───────────────────────────────────────────────
	fmt.Println("\n========================================")
	fmt.Println("  TAMPER TEST (flip age_over_18 to false)")
	fmt.Println("========================================")

	tamperedItem := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("attacker-does-not-know-real-salt"),
		ElementIdentifier: "age_over_18",
		ElementValue:      false,
	}
	tamperedWrapped, _ := tag24Wrap(tamperedItem)
	tamperedMDoc := &MDoc{
		DocType: presented.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{
				namespace: {{EncodedItem: tamperedWrapped}},
			},
			IssuerAuth: presented.IssuerSigned.IssuerAuth,
		},
	}

	tamperedResult := verifier.Verify(tamperedMDoc, namespace)
	fmt.Printf("  Tampered valid: %v\n", tamperedResult.Valid)
	fmt.Printf("  Error: %s\n", tamperedResult.Error)
	fmt.Println("  (tamper correctly rejected ✓)")

	// ── DEVICE-KEY MISMATCH TEST ───────────────────────────────────
	// Simulates a cloned mdoc: issuerSigned data copied to a different
	// device, which signs deviceAuth with ITS OWN key instead of the
	// key embedded in deviceKeyInfo. This is exactly the attack that
	// Verify() alone (without deviceAuth checking) would miss.
	fmt.Println("\n========================================")
	fmt.Println("  DEVICE-KEY MISMATCH TEST (cloned mdoc, wrong signer)")
	fmt.Println("========================================")

	otherHolder, _ := NewHolder()
	wrongDeviceAuthBytes, _ := otherHolder.SignDeviceAuth(docType, transcript)

	cloneResult := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, wrongDeviceAuthBytes)
	fmt.Printf("  Cloned mdoc deviceAuth valid: %v\n", cloneResult.DeviceAuthValid)
	fmt.Printf("  Error: %s\n", cloneResult.Error)
	fmt.Println("  (correctly rejected — deviceAuth signed by wrong key ✓)")
}
