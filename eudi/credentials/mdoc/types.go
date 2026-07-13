package mdoc

import "time"

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
	DigestID          uint64 `cbor:"digestID"`          // index into ValueDigests map
	Random            []byte `cbor:"random"`            // ≥16 byte salt — prevents brute force
	ElementIdentifier string `cbor:"elementIdentifier"` // attribute name e.g. "age_over_18"
	ElementValue      any    `cbor:"elementValue"`      // attribute value e.g. true
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
	_                     struct{} `cbor:",toarray"`
	DeviceEngagementBytes []byte   // from QR code / NFC tap
	EReaderKeyBytes       []byte   // verifier's ephemeral public key
	Handover              any      // session-specific binding data
}
