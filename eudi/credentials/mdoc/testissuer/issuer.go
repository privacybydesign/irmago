package testissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// AVDocType is the Age Verification doctype per the EU AV spec.
const AVDocType = "eu.europa.ec.av.1"

// AVNamespace is the single namespace used by the AV credential.
const AVNamespace = "eu.europa.ec.av.1"

// tagEncodedCBOR is CBOR tag 24 — "Encoded CBOR data item" (RFC 8949 §3.4.5).
const tagEncodedCBOR uint64 = 24

// coseAlgES256 is the COSE algorithm identifier for ECDSA-P256-SHA256 (RFC 9053).
const coseAlgES256 = -7

// coseHeaderAlg is COSE header parameter "alg".
const coseHeaderAlg = 1

// coseHeaderX5Chain is COSE header parameter "x5chain" (RFC 9360).
const coseHeaderX5Chain = 33

// randomSaltSize is the length of the per-element salt. 16 bytes gives
// 128 bits of entropy — enough to make brute-forcing a boolean "age_over_N"
// element infeasible.
const randomSaltSize = 16

// maxValidity is the spec-imposed cap (AV spec §7.2): a single-use attestation
// SHALL be valid for at most three months.
const maxValidity = 90 * 24 * time.Hour

// AVRequest describes which age-proof claims the caller wants included.
type AVRequest struct {
	AgeOver18 bool
	AgeOverNN map[int]bool

	Signed     time.Time
	ValidFrom  time.Time
	ValidUntil time.Time
}

// AVCredential is the output of a successful issuance.
type AVCredential struct {
	IssuerSignedCBOR []byte
	DocType          string

	IACACert *x509.Certificate
	IACAKey  *ecdsa.PrivateKey

	DSCert *x509.Certificate
	DSKey  *ecdsa.PrivateKey

	DeviceKey *ecdsa.PrivateKey
}

// BuildAVCredential produces a fake Age Verification mdoc credential with a
// fresh IACA/DS/Device key triple.
func BuildAVCredential(req AVRequest) (*AVCredential, error) {
	now := time.Now().UTC().Truncate(time.Second)
	signed := req.Signed
	if signed.IsZero() {
		signed = now
	}
	validFrom := req.ValidFrom
	if validFrom.IsZero() {
		validFrom = now
	}
	validUntil := req.ValidUntil
	if validUntil.IsZero() {
		validUntil = validFrom.Add(maxValidity)
	}
	if validUntil.Sub(validFrom) > maxValidity {
		return nil, fmt.Errorf("testissuer: validity window exceeds max %s", maxValidity)
	}

	iacaKey, iacaCert, err := mintIACA(signed)
	if err != nil {
		return nil, fmt.Errorf("mint IACA: %w", err)
	}
	dsKey, dsCert, err := mintDS(iacaKey, iacaCert, signed)
	if err != nil {
		return nil, fmt.Errorf("mint DS: %w", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}

	items, err := buildItems(req)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("testissuer: no age attributes requested")
	}

	issuerSigned, err := buildIssuerSigned(items, deviceKey, dsKey, dsCert, signed, validFrom, validUntil)
	if err != nil {
		return nil, err
	}

	return &AVCredential{
		IssuerSignedCBOR: issuerSigned,
		DocType:          AVDocType,
		IACACert:         iacaCert,
		IACAKey:          iacaKey,
		DSCert:           dsCert,
		DSKey:            dsKey,
		DeviceKey:        deviceKey,
	}, nil
}

// ---- certificate minting ---------------------------------------------------

func mintIACA(now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Fake IACA (testissuer)",
			Organization: []string{"Yivi testissuer"},
			Country:      []string{"NL"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}

func mintDS(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Fake Document Signer (testissuer)",
			Organization: []string{"Yivi testissuer"},
			Country:      []string{"NL"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(3 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iaca, &key.PublicKey, iacaKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}

func randomSerial() (*big.Int, error) {
	// 20 bytes is the CAB Forum minimum for publicly trusted CAs and more than
	// sufficient entropy for a synthetic test PKI.
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, limit)
}

// ---- attribute items -------------------------------------------------------

// issuerSignedItemRaw mirrors the IssuerSignedItem CBOR map on the wire. We
// keep ElementValue as cbor.RawMessage so the caller controls its encoding.
type issuerSignedItemRaw struct {
	DigestID          uint64          `cbor:"digestID"`
	Random            []byte          `cbor:"random"`
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

type builtItem struct {
	digestID    uint64
	identifier  string
	taggedBytes []byte // the on-wire #6.24(bstr(item)) encoding
	digest      []byte // SHA-256 of taggedBytes
}

func buildItems(req AVRequest) ([]builtItem, error) {
	// Collect the (identifier, value) pairs in a stable order so the on-wire
	// ordering is deterministic for a given input.
	type pair struct {
		id  string
		val bool
	}
	var pairs []pair
	if req.AgeOver18 {
		pairs = append(pairs, pair{"age_over_18", true})
	}
	// Walk AgeOverNN in ascending N for determinism.
	ns := make([]int, 0, len(req.AgeOverNN))
	for n := range req.AgeOverNN {
		ns = append(ns, n)
	}
	sortInts(ns)
	for _, n := range ns {
		pairs = append(pairs, pair{fmt.Sprintf("age_over_%d", n), req.AgeOverNN[n]})
	}

	items := make([]builtItem, 0, len(pairs))
	for i, p := range pairs {
		randBytes := make([]byte, randomSaltSize)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, err
		}
		valueCBOR, err := cbor.Marshal(p.val)
		if err != nil {
			return nil, err
		}
		itemCBOR, err := cbor.Marshal(issuerSignedItemRaw{
			DigestID:          uint64(i),
			Random:            randBytes,
			ElementIdentifier: p.id,
			ElementValue:      valueCBOR,
		})
		if err != nil {
			return nil, err
		}
		taggedBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: itemCBOR})
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(taggedBytes)
		items = append(items, builtItem{
			digestID:    uint64(i),
			identifier:  p.id,
			taggedBytes: taggedBytes,
			digest:      h[:],
		})
	}
	return items, nil
}

// ---- IssuerSigned + COSE_Sign1 ---------------------------------------------

type coseKeyEC2 struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type deviceKeyInfo struct {
	DeviceKey coseKeyEC2 `cbor:"deviceKey"`
}

type validityInfo struct {
	Signed     time.Time `cbor:"signed"`
	ValidFrom  time.Time `cbor:"validFrom"`
	ValidUntil time.Time `cbor:"validUntil"`
}

type mso struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   deviceKeyInfo                `cbor:"deviceKeyInfo"`
	DocType         string                       `cbor:"docType"`
	ValidityInfo    validityInfo                 `cbor:"validityInfo"`
}

type issuerSignedEncode struct {
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth []any                        `cbor:"issuerAuth"`
}

// encMode emits CBOR with tagged RFC 3339 times (tag 0), as ISO 18013-5 expects.
var encMode = func() cbor.EncMode {
	m, err := cbor.EncOptions{
		TimeTag: cbor.EncTagRequired,
		Time:    cbor.TimeRFC3339,
	}.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func buildIssuerSigned(
	items []builtItem,
	deviceKey *ecdsa.PrivateKey,
	dsKey *ecdsa.PrivateKey,
	dsCert *x509.Certificate,
	signed, validFrom, validUntil time.Time,
) ([]byte, error) {
	valueDigests := map[string]map[uint64][]byte{
		AVNamespace: make(map[uint64][]byte, len(items)),
	}
	for _, it := range items {
		valueDigests[AVNamespace][it.digestID] = it.digest
	}

	coseKey := ecPubToCoseKeyEC2(&deviceKey.PublicKey)
	msoData := mso{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    valueDigests,
		DeviceKeyInfo:   deviceKeyInfo{DeviceKey: coseKey},
		DocType:         AVDocType,
		ValidityInfo: validityInfo{
			Signed:     signed,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		},
	}
	msoBytes, err := encMode.Marshal(msoData)
	if err != nil {
		return nil, fmt.Errorf("encode MSO: %w", err)
	}
	payload, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: msoBytes})
	if err != nil {
		return nil, fmt.Errorf("wrap MSO in tag 24: %w", err)
	}

	issuerAuth, err := coseSign1Sign(payload, dsKey, dsCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("COSE_Sign1: %w", err)
	}

	nameSpaceItems := make([]cbor.RawMessage, len(items))
	for i, it := range items {
		nameSpaceItems[i] = it.taggedBytes
	}
	encoded, err := cbor.Marshal(issuerSignedEncode{
		NameSpaces: map[string][]cbor.RawMessage{AVNamespace: nameSpaceItems},
		IssuerAuth: issuerAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("encode IssuerSigned: %w", err)
	}
	return encoded, nil
}

func ecPubToCoseKeyEC2(pub *ecdsa.PublicKey) coseKeyEC2 {
	const (
		cosekty2EC2   = 2 // COSE kty for EC2 (RFC 9053 §7.1)
		coseCrvP256   = 1 // COSE crv for P-256 (RFC 9053 §7.1)
		coordByteSize = 32
	)
	return coseKeyEC2{
		Kty: cosekty2EC2,
		Crv: coseCrvP256,
		X:   padLeft(pub.X.Bytes(), coordByteSize),
		Y:   padLeft(pub.Y.Bytes(), coordByteSize),
	}
}

// coseSign1Sign returns the 4-element CBOR array representing a COSE_Sign1
// per RFC 9052 §4.2: [protected, unprotected, payload, signature].
func coseSign1Sign(payload []byte, dsKey *ecdsa.PrivateKey, dsCertDER []byte) ([]any, error) {
	protectedMap := map[int]int{coseHeaderAlg: coseAlgES256}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		return nil, err
	}
	unprotected := map[int]any{coseHeaderX5Chain: dsCertDER}

	sigStruct, err := cbor.Marshal([]any{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad
		payload,
	})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(sigStruct)
	r, s, err := ecdsa.Sign(rand.Reader, dsKey, h[:])
	if err != nil {
		return nil, err
	}
	sig := encodeES256Signature(r, s)

	return []any{
		protectedBytes,
		unprotected,
		payload,
		sig,
	}, nil
}

// encodeES256Signature converts the (r, s) pair from ecdsa.Sign into the
// fixed-width 64-byte r‖s encoding COSE uses for ES256 (RFC 8152 §8.1).
func encodeES256Signature(r, s *big.Int) []byte {
	const coordLen = 32
	out := make([]byte, 2*coordLen)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[coordLen-len(rb):coordLen], rb)
	copy(out[2*coordLen-len(sb):], sb)
	return out
}

// ---- small helpers ---------------------------------------------------------

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func sortInts(xs []int) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
