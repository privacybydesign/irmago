package mdoc

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// ZERO-KNOWLEDGE PROOFS — the ZkSystemSpec mechanism of
// ISO/IEC DIS 18013-5 (Second Edition) 10.2.7
// ============================================================
//
// This file is the wire format only: the request a reader sends to ask for a
// proof instead of a disclosure, and the document a wallet returns in place of
// one. Producing and checking the proof itself is a separate concern behind the
// ZkSystem interface in zkp_system.go, because it needs a native library this
// module deliberately does not link (see that file).
//
// Why this exists at all: the EUDI Age Verification Blueprint Annex A 8 makes a
// zero-knowledge proof the *preferred* way to present a Proof of Age
// attestation — "the AVI SHALL support the generation of Zero-Knowledge Proofs"
// wherever the device can — and names exactly one system as in scope,
// longfellow-libzk-v1. Presenting the plain mdoc of A.6 stays conformant only
// as the fallback for devices that cannot prove.
//
// What the proof replaces is not the checks a verifier makes but the evidence
// it makes them on. The four statements A.8 requires a proof to demonstrate map
// one-to-one onto what Verifier already does in cleartext: the attestation
// carries a signature verifiable under the AP's key, the requested attribute is
// present and true, the wallet can sign the session nonce under the key bound
// into the attestation, and the attestation is inside its validity period. In a
// ZK presentation the MSO, the issuer signature, the device signature and the
// salts never leave the device; only the named elements, their values, and the
// issuer's certificate do.
//
// The byte shapes here are not readable from the 2021 edition of ISO/IEC
// 18013-5, which has no ZK at all, and the second edition is a paywalled draft.
// They follow Multipaz (org.multipaz.mdoc.zkp), which is both the reference the
// AV interop events are run against and the implementation the Longfellow
// authors' own test vectors are exercised through. Conformance here means
// "matches Multipaz"; every structure below was written against its Kotlin
// source and the field names are its field names, not invented ones.

// ZkSystemLongfellowV1 is the only ZK system in scope for this version of the
// AV profile. A.8 is explicit that breadth is not a virtue here: "Support for
// any other Zero-Knowledge Proof system does not constitute conformance with
// this profile." The identifier is versioned precisely so a later profile can
// add or replace it, which is why it is a constant to compare against rather
// than a default to fall back on.
const ZkSystemLongfellowV1 = "longfellow-libzk-v1"

// The parameters a longfellow-libzk-v1 ZkSystemSpec carries, per A.8 and
// 10.2.7. Together they identify one circuit exactly: a circuit is built for a
// fixed number of attributes and a fixed pair of block-encoding sizes, and the
// hash pins the compiled bytes.
//
// circuit_hash is the load-bearing one for a relying party. A.8 requires the RP
// to check it against the scheme owner's published set of accepted circuits
// *before* verifying the proof and to reject anything outside that set — see
// AcceptedCircuits in zkp_system.go for why that ordering is not optional.
const (
	ZkParamCircuitHash   = "circuit_hash"
	ZkParamVersion       = "version"
	ZkParamNumAttributes = "num_attributes"
	ZkParamBlockEncHash  = "block_enc_hash"
	ZkParamBlockEncSig   = "block_enc_sig"
)

// zkEncMode is the encoder for every structure in this file.
//
// Two settings, both load-bearing. TimeRFC3339 with a required tag makes
// ZkDocumentData.Timestamp the `tdate` 10.2.7 types it as, for the same reason
// tdateEncMode exists for ValidityInfo — the library default is a bare epoch
// integer that no conformant parser expects. SortCanonical makes the encoding
// deterministic: ZkDocumentData holds Go maps keyed by namespace, and with the
// library's default SortNone the same document would serialize to different
// bytes on consecutive calls, which is both a violation of 8.1's canonical-CBOR
// rule and an unpleasant surprise for anything that hashes or caches the result.
var zkEncMode, _ = cbor.EncOptions{
	Time:    cbor.TimeRFC3339,
	TimeTag: cbor.EncTagRequired,
	Sort:    cbor.SortCanonical,
}.EncMode()

// ============================================================
// ZkSystemSpec — the identity of one circuit
// ============================================================

// ZkSystemSpec names a ZK system and the parameters that pick one circuit
// within it. Readers send a list of the specs they accept; a wallet answers
// with a proof produced under exactly one of them, echoing its ID back in the
// response so the verifier knows which circuit to load.
//
// Params is untyped because 10.2.7 leaves the parameter set to the system: the
// five longfellow constants above are what this profile uses, but the mechanism
// is general and a spec carrying parameters this build has never heard of must
// still round-trip rather than fail to decode. Use the typed accessors for the
// ones that are known.
type ZkSystemSpec struct {
	// ID is the spec's identifier, opaque to everyone but the system that
	// minted it. Multipaz composes it as "<system>_<circuit filename>"; nothing
	// may parse it, and a wallet must treat it as a label to echo back.
	ID string

	// System is the ZK system name — ZkSystemLongfellowV1 for anything
	// conformant with this version of the profile.
	System string

	// Params holds the system-specific parameters as decoded CBOR values:
	// strings, integers (as uint64/int64), booleans and floats.
	Params map[string]any
}

// StringParam returns a string-valued parameter.
func (s ZkSystemSpec) StringParam(key string) (string, bool) {
	value, ok := s.Params[key].(string)
	return value, ok
}

// IntParam returns an integer-valued parameter, normalizing over the several Go
// types a CBOR integer can decode into depending on its sign and magnitude. A
// caller asking for num_attributes should not have to care that the encoder
// chose a positive-integer major type.
func (s ZkSystemSpec) IntParam(key string) (int64, bool) {
	switch value := s.Params[key].(type) {
	case int64:
		return value, true
	case uint64:
		return int64(value), true
	case int:
		return int64(value), true
	}
	return 0, false
}

// CircuitHash returns the circuit_hash parameter, the value A.8 requires a
// relying party to check against the accepted set before verifying a proof.
func (s ZkSystemSpec) CircuitHash() (string, bool) { return s.StringParam(ZkParamCircuitHash) }

// Version returns the circuit's version parameter.
func (s ZkSystemSpec) Version() (int64, bool) { return s.IntParam(ZkParamVersion) }

// NumAttributes returns how many attributes the circuit is built for. A circuit
// proves a fixed number of statements, so a request for three elements cannot
// be answered with a two-attribute circuit; this is what the matching in
// ZkSystem.MatchingSpec is mostly about.
func (s ZkSystemSpec) NumAttributes() (int64, bool) { return s.IntParam(ZkParamNumAttributes) }

// SameCircuit reports whether two specs identify the same circuit. Deliberately
// not an ID comparison: the ID is the minting implementation's own label, and a
// reader's spec and a wallet's spec for one circuit are assembled
// independently, so they agree on the parameters long before they agree on a
// name. The three fields compared are what the circuit actually is.
func (s ZkSystemSpec) SameCircuit(other ZkSystemSpec) bool {
	if s.System != other.System {
		return false
	}
	hashA, okA := s.CircuitHash()
	hashB, okB := other.CircuitHash()
	if !okA || !okB || hashA != hashB {
		return false
	}
	versionA, _ := s.Version()
	versionB, _ := other.Version()
	countA, _ := s.NumAttributes()
	countB, _ := other.NumAttributes()
	return versionA == versionB && countA == countB
}

// zkSystemSpecWire is the CBOR shape of a spec inside a ZkRequest:
//
//	{"zkSystemId": tstr, "system": tstr, "params": {* tstr => any}}
type zkSystemSpecWire struct {
	ZkSystemID string         `cbor:"zkSystemId"`
	System     string         `cbor:"system"`
	Params     map[string]any `cbor:"params"`
}

func (s ZkSystemSpec) wire() zkSystemSpecWire {
	params := s.Params
	if params == nil {
		// An absent params map and an empty one are the same statement, but
		// only one of them encodes as a CBOR map rather than null.
		params = map[string]any{}
	}
	return zkSystemSpecWire{ZkSystemID: s.ID, System: s.System, Params: params}
}

func (w zkSystemSpecWire) spec() ZkSystemSpec {
	return ZkSystemSpec{ID: w.ZkSystemID, System: w.System, Params: w.Params}
}

// ============================================================
// ZkRequest — asking for a proof instead of a disclosure
// ============================================================

// ZkRequest is what a reader adds to its request to say it will take a
// zero-knowledge proof: the specs it can verify, and whether a plain mdoc is
// still acceptable.
//
// ZkRequired is the field that decides the fallback A.8 mandates. False is the
// profile's normal posture — the RP "SHALL be able to verify both a
// Zero-Knowledge Proof presentation and the plain ISO mDoc fallback
// presentation" — so a wallet that cannot prove, because the device lacks the
// support or because no offered spec matches a circuit it holds, answers with
// the A.6 presentation and the session succeeds. True means the reader has
// opted out of that and a wallet with no usable circuit must fail the session
// rather than silently disclose in the clear, which is the one case where
// falling back would hand over more than the user was asked to agree to.
type ZkRequest struct {
	SystemSpecs []ZkSystemSpec
	ZkRequired  bool
}

type zkRequestWire struct {
	SystemSpecs []zkSystemSpecWire `cbor:"systemSpecs"`
	ZkRequired  bool               `cbor:"zkRequired"`
}

// MarshalCBOR encodes the request as 10.2.7's zkRequest map.
func (r ZkRequest) MarshalCBOR() ([]byte, error) {
	specs := make([]zkSystemSpecWire, 0, len(r.SystemSpecs))
	for _, spec := range r.SystemSpecs {
		specs = append(specs, spec.wire())
	}
	return zkEncMode.Marshal(zkRequestWire{SystemSpecs: specs, ZkRequired: r.ZkRequired})
}

// UnmarshalCBOR decodes a zkRequest map.
func (r *ZkRequest) UnmarshalCBOR(data []byte) error {
	var wire zkRequestWire
	if err := Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode zkRequest: %w", err)
	}
	specs := make([]ZkSystemSpec, 0, len(wire.SystemSpecs))
	for _, spec := range wire.SystemSpecs {
		specs = append(specs, spec.spec())
	}
	r.SystemSpecs = specs
	r.ZkRequired = wire.ZkRequired
	return nil
}

// ============================================================
// ZkDocument — the presentation itself
// ============================================================

// ZkSignedItem is one element a proof opens: its identifier and its value.
//
// ElementValue is cbor.RawMessage rather than `any` on purpose. The value is
// part of the statement the circuit proves, and the prover and verifier both
// feed it to the native library as encoded CBOR bytes, so those bytes have to
// survive the trip unchanged. Decoding to `any` and re-encoding does not
// guarantee that: a full-date is tag 1004 around a string, a height is a
// positive integer whose encoding depends on its magnitude, and any tag or
// integer width the round trip fails to reproduce exactly turns a valid proof
// into a verification failure with nothing naming the cause. Holding the raw
// bytes makes the question moot.
type ZkSignedItem struct {
	ElementIdentifier string
	ElementValue      cbor.RawMessage
}

// ZkDocumentData is the cleartext half of a ZK presentation: what the proof is
// about, stated openly, so the verifier knows which statements the proof is
// claiming to have established.
//
// It is not evidence. Every field here is attacker-controlled until the proof
// over it verifies — a wallet can put any docType, any element value and any
// timestamp in this map. The proof is what binds them, which is why
// ZkSystem.VerifyProof takes the whole document and why nothing downstream may
// read IssuerSigned before that call has returned nil.
//
// Note what is absent compared with an ordinary Document: there is no MSO, no
// issuerAuth, no device signature, and no salts. That is the point — they are
// the linkable parts. What remains is the elements the reader asked for, and
// the issuer's certificate chain, which the verifier needs in the clear because
// the proof is *relative to* an issuer public key rather than proving anything
// about which issuer signed.
type ZkDocumentData struct {
	// ZkSystemSpecID echoes the ID of the spec the proof was produced under, so
	// the verifier can find the same circuit. It is a label, not a claim: the
	// verifier resolves it against the specs it offered, never by parsing it.
	ZkSystemSpecID string

	DocType string

	// Timestamp is the time the proof asserts it was generated at, and is an
	// input to the circuit's validity-period check rather than a note about
	// when this ran — statement four of A.8, "the Proof of Age attestation is
	// within its validity period", is proved against this instant.
	//
	// Whole seconds only: the Longfellow prover formats it as a 20-character
	// "2023-11-02T09:00:00Z" and a fractional part does not survive. It is
	// truncated at construction rather than at encode so the value a caller
	// reads back is the value that was proved.
	Timestamp time.Time

	// IssuerSigned holds the opened elements per namespace. The slice preserves
	// the order they were proved in, which the native verifier's attribute
	// array is sensitive to.
	IssuerSigned map[string][]ZkSignedItem

	// DeviceSigned is the holder-asserted equivalent. Always empty today: the
	// Longfellow circuits prove over issuer-signed elements only, and the AV
	// profile has no holder-asserted claims to begin with. Modelled because the
	// structure is 10.2.7's and a document that carries them must round-trip.
	DeviceSigned map[string][]ZkSignedItem

	// MsoX5Chain is the issuer's certificate chain, in the clear. The verifier
	// needs it twice over: to establish that the signing key belongs to a
	// trusted AP at all, through the same trust model an ordinary presentation
	// goes through, and to hand the circuit the P-256 coordinates the proof is
	// stated against.
	MsoX5Chain []*x509.Certificate
}

// ZkDocument is a document presented as a proof: the cleartext claim and the
// proof that establishes it. It appears in a DeviceResponse's zkDocuments array
// where an ordinary presentation would put a Document in documents.
type ZkDocument struct {
	DocumentData ZkDocumentData
	Proof        []byte
}

// NewZkDocumentData assembles the cleartext half of a presentation, truncating
// the timestamp to the whole second the prover will actually use.
func NewZkDocumentData(
	specID, docType string,
	timestamp time.Time,
	issuerSigned map[string][]ZkSignedItem,
	chain []*x509.Certificate,
) ZkDocumentData {
	return ZkDocumentData{
		ZkSystemSpecID: specID,
		DocType:        docType,
		Timestamp:      timestamp.UTC().Truncate(time.Second),
		IssuerSigned:   issuerSigned,
		DeviceSigned:   map[string][]ZkSignedItem{},
		MsoX5Chain:     chain,
	}
}

type zkSignedItemWire struct {
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

type zkDocumentDataWire struct {
	ZkSystemID   string                        `cbor:"zkSystemId"`
	DocType      string                        `cbor:"docType"`
	Timestamp    time.Time                     `cbor:"timestamp"`
	IssuerSigned map[string][]zkSignedItemWire `cbor:"issuerSigned"`
	DeviceSigned map[string][]zkSignedItemWire `cbor:"deviceSigned"`
	MsoX5Chain   cbor.RawMessage               `cbor:"msoX5chain,omitempty"`
}

type zkDocumentWire struct {
	Proof        []byte          `cbor:"proof"`
	DocumentData cbor.RawMessage `cbor:"documentData"`
}

func signedItemsToWire(namespaces map[string][]ZkSignedItem) map[string][]zkSignedItemWire {
	// Never nil: 10.2.7 has both maps present, and an omitted one decodes
	// elsewhere as a missing key rather than an empty namespace set.
	wire := make(map[string][]zkSignedItemWire, len(namespaces))
	for namespace, items := range namespaces {
		encoded := make([]zkSignedItemWire, 0, len(items))
		for _, item := range items {
			encoded = append(encoded, zkSignedItemWire{
				ElementIdentifier: item.ElementIdentifier,
				ElementValue:      item.ElementValue,
			})
		}
		wire[namespace] = encoded
	}
	return wire
}

func signedItemsFromWire(wire map[string][]zkSignedItemWire) map[string][]ZkSignedItem {
	namespaces := make(map[string][]ZkSignedItem, len(wire))
	for namespace, items := range wire {
		decoded := make([]ZkSignedItem, 0, len(items))
		for _, item := range items {
			decoded = append(decoded, ZkSignedItem{
				ElementIdentifier: item.ElementIdentifier,
				ElementValue:      item.ElementValue,
			})
		}
		namespaces[namespace] = decoded
	}
	return namespaces
}

// encodeCertChain encodes a certificate chain the way COSE's x5chain header
// does, which is what Multipaz's X509CertChain writes here: a bare byte string
// when there is exactly one certificate, an array of byte strings otherwise.
// The asymmetry is not ours to smooth over — a verifier written against the
// array form alone rejects the single-certificate case every real AV
// presentation produces.
func encodeCertChain(chain []*x509.Certificate) (cbor.RawMessage, error) {
	switch len(chain) {
	case 0:
		return nil, nil
	case 1:
		encoded, err := zkEncMode.Marshal(chain[0].Raw)
		if err != nil {
			return nil, fmt.Errorf("encode msoX5chain: %w", err)
		}
		return encoded, nil
	default:
		raw := make([][]byte, 0, len(chain))
		for _, cert := range chain {
			raw = append(raw, cert.Raw)
		}
		encoded, err := zkEncMode.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("encode msoX5chain: %w", err)
		}
		return encoded, nil
	}
}

func decodeCertChain(raw cbor.RawMessage) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var single []byte
	if err := Unmarshal(raw, &single); err == nil {
		cert, err := x509.ParseCertificate(single)
		if err != nil {
			return nil, fmt.Errorf("parse msoX5chain certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}

	var multiple [][]byte
	if err := Unmarshal(raw, &multiple); err != nil {
		return nil, fmt.Errorf("decode msoX5chain: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(multiple))
	for i, der := range multiple {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse msoX5chain[%d]: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// MarshalCBOR encodes the cleartext half of a presentation.
func (d ZkDocumentData) MarshalCBOR() ([]byte, error) {
	chain, err := encodeCertChain(d.MsoX5Chain)
	if err != nil {
		return nil, err
	}
	return zkEncMode.Marshal(zkDocumentDataWire{
		ZkSystemID:   d.ZkSystemSpecID,
		DocType:      d.DocType,
		Timestamp:    d.Timestamp.UTC().Truncate(time.Second),
		IssuerSigned: signedItemsToWire(d.IssuerSigned),
		DeviceSigned: signedItemsToWire(d.DeviceSigned),
		MsoX5Chain:   chain,
	})
}

// UnmarshalCBOR decodes the cleartext half of a presentation. Nothing it
// produces may be believed until ZkSystem.VerifyProof has accepted the proof
// over it; see the note on ZkDocumentData.
func (d *ZkDocumentData) UnmarshalCBOR(data []byte) error {
	var wire zkDocumentDataWire
	if err := Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode zkDocumentData: %w", err)
	}
	chain, err := decodeCertChain(wire.MsoX5Chain)
	if err != nil {
		return err
	}
	d.ZkSystemSpecID = wire.ZkSystemID
	d.DocType = wire.DocType
	d.Timestamp = wire.Timestamp
	d.IssuerSigned = signedItemsFromWire(wire.IssuerSigned)
	d.DeviceSigned = signedItemsFromWire(wire.DeviceSigned)
	d.MsoX5Chain = chain
	return nil
}

// MarshalCBOR encodes the document as 10.2.7's ZkDocument:
//
//	{"proof": bstr, "documentData": #6.24(bstr .cbor ZkDocumentData)}
//
// documentData is tag-24 wrapped for the same reason every other embedded
// structure in 18013-5 is: it fixes one byte sequence as the thing being
// referred to, rather than leaving the receiver to re-encode a decoded map and
// hope it lands on the same bytes.
func (z ZkDocument) MarshalCBOR() ([]byte, error) {
	inner, err := z.DocumentData.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	wrapped, err := tag24WrapBytes(inner)
	if err != nil {
		return nil, fmt.Errorf("wrap zkDocumentData: %w", err)
	}
	return zkEncMode.Marshal(zkDocumentWire{Proof: z.Proof, DocumentData: wrapped})
}

// UnmarshalCBOR decodes a ZkDocument.
func (z *ZkDocument) UnmarshalCBOR(data []byte) error {
	var wire zkDocumentWire
	if err := Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode zkDocument: %w", err)
	}
	if len(wire.Proof) == 0 {
		return fmt.Errorf("zkDocument has no proof")
	}
	documentData, err := tag24Unwrap[cbor.RawMessage](wire.DocumentData)
	if err != nil {
		return fmt.Errorf("unwrap zkDocumentData: %w", err)
	}
	if err := z.DocumentData.UnmarshalCBOR(documentData); err != nil {
		return err
	}
	z.Proof = wire.Proof
	return nil
}
