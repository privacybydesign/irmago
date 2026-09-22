package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/zk"
)

// ============================================================
// PROVER SYSTEM — the adapter over the byte-oriented boundary
// ============================================================
//
// ProverSystem is the one place that speaks both languages. On one side it is a
// ZkSystem: it takes MDoc, SessionTranscript and ZkSystemSpec, the types the
// rest of this package and the presentation session are written in. On the
// other it is a caller of zk.System, which knows only bytes.
//
// The split exists so the native prover module never has to import irmago.
// Everything domain-shaped stops here: the CBOR encoding, the certificate
// parsing, the AV profile's identifier convention, the ordering rules. What
// crosses into zk is encoded bytes and strings.
//
// Nothing constructs a ProverSystem inside irmago. The application wires one up
// when it has a native prover to wire, and a build without one simply has no ZK
// system registered — which §A.8 makes the ordinary fallback rather than an
// error. See package zk for why the dependency runs in that direction.

// ProverSystem implements ZkSystem over a zk.System.
type ProverSystem struct {
	system zk.System
}

// NewProverSystem adapts a native ZK system into a ZkSystem.
func NewProverSystem(system zk.System) *ProverSystem {
	return &ProverSystem{system: system}
}

// Ensure the adapter actually satisfies the interface it exists to satisfy.
var _ ZkSystem = (*ProverSystem)(nil)

// Name is the underlying system's identifier.
func (p *ProverSystem) Name() string {
	if p == nil || p.system == nil {
		return ""
	}
	return p.system.Name()
}

// SystemSpecs turns the circuits the native system holds into the specs a
// reader offers and a wallet matches against.
//
// The identifier follows the AV profile's composite convention, which is
// Multipaz's circuit-filename order with the system name in front:
//
//	<system>_<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<hash>
//
// Worth knowing that this is one of two conventions in the wild. Google's own
// reference verifier service uses zkSystemId both as a circuit filename and in
// find_zk_spec, where it strcmps the bare hash — so an RP running that code and
// a wallet following this profile disagree about what the field holds. We
// follow the profile, because that is what the captured EUDI AV traffic and
// Multipaz both emit; a verifier expecting a bare hash has to take the trailing
// component. Nothing may parse this identifier to recover the parameters: the
// params map is where they live, and the ID is a label to echo back.
func (p *ProverSystem) SystemSpecs() []ZkSystemSpec {
	if p == nil || p.system == nil {
		return nil
	}
	circuits := p.system.Circuits()
	specs := make([]ZkSystemSpec, 0, len(circuits))
	for _, circuit := range circuits {
		specs = append(specs, specForCircuit(circuit))
	}
	return specs
}

func specForCircuit(circuit zk.Circuit) ZkSystemSpec {
	return ZkSystemSpec{
		ID: fmt.Sprintf("%s_%d_%d_%d_%d_%s",
			circuit.System, circuit.Version, circuit.NumAttributes,
			circuit.BlockEncHash, circuit.BlockEncSig, circuit.Hash),
		System: circuit.System,
		Params: map[string]any{
			ZkParamVersion:       int64(circuit.Version),
			ZkParamNumAttributes: int64(circuit.NumAttributes),
			ZkParamBlockEncHash:  int64(circuit.BlockEncHash),
			ZkParamBlockEncSig:   int64(circuit.BlockEncSig),
			ZkParamCircuitHash:   circuit.Hash,
		},
	}
}

// MatchingSpec picks the circuit to answer a request with: one the reader
// offered, that this system holds, built for exactly numAttributes. Where
// several qualify the newest version wins.
//
// The comparison is SameCircuit rather than an ID comparison, because the
// reader's spec and ours are assembled independently and agree on the
// parameters long before they agree on a name. The spec returned is OURS, so
// the ID echoed back in the response is one this system can resolve.
func (p *ProverSystem) MatchingSpec(offered []ZkSystemSpec, numAttributes int) (ZkSystemSpec, bool) {
	if p == nil || p.system == nil {
		return ZkSystemSpec{}, false
	}

	var best ZkSystemSpec
	var bestVersion int64 = -1
	found := false

	for _, mine := range p.SystemSpecs() {
		count, ok := mine.NumAttributes()
		if !ok || count != int64(numAttributes) {
			continue
		}
		for _, theirs := range offered {
			if !mine.SameCircuit(theirs) {
				continue
			}
			version, _ := mine.Version()
			if version > bestVersion {
				best, bestVersion, found = mine, version, true
			}
			break
		}
	}
	return best, found
}

// GenerateProof proves the statements of §A.8 about document.
//
// The document must already carry its DeviceSigned. That is not this adapter
// being fussy: the native prover refuses a document without one, because one of
// the four statements is about a device signature over the session transcript.
// So the ordinary presentation path runs first and unchanged, and the proof is
// taken over its result.
func (p *ProverSystem) GenerateProof(
	spec ZkSystemSpec,
	document MDoc,
	transcript SessionTranscript,
	timestamp time.Time,
) (*ZkDocument, error) {
	if p == nil || p.system == nil {
		return nil, fmt.Errorf("no zk system")
	}
	if document.DeviceSigned == nil {
		return nil, fmt.Errorf(
			"document %s has no deviceSigned: the presentation path must run before the proof is taken over it",
			document.DocType)
	}

	circuit, ok := spec.CircuitHash()
	if !ok {
		return nil, fmt.Errorf("zk system spec %q carries no %s", spec.ID, ZkParamCircuitHash)
	}

	items, err := orderedElements(document)
	if err != nil {
		return nil, err
	}

	chain, err := issuerChain(document)
	if err != nil {
		return nil, err
	}
	keyX, keyY, err := issuerKeyCoordinates(chain)
	if err != nil {
		return nil, err
	}

	encodedResponse, err := cbor.Marshal(NewDeviceResponse(document))
	if err != nil {
		return nil, fmt.Errorf("encode DeviceResponse for proving: %w", err)
	}
	encodedTranscript, err := cbor.Marshal(transcript)
	if err != nil {
		return nil, fmt.Errorf("encode session transcript for proving: %w", err)
	}

	request := zk.ProofRequest{
		Circuit:        circuit,
		DocType:        document.DocType,
		DeviceResponse: encodedResponse,
		IssuerKeyX:     keyX,
		IssuerKeyY:     keyY,
		Transcript:     encodedTranscript,
		Attributes:     zkAttributesOf(items),
		Timestamp:      timestamp,
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("proof request for %s: %w", document.DocType, err)
	}

	proof, err := p.system.Prove(request)
	if err != nil {
		return nil, fmt.Errorf("prove %s under circuit %s: %w", document.DocType, circuit, err)
	}
	if len(proof) == 0 {
		return nil, fmt.Errorf("prover returned an empty proof for %s", document.DocType)
	}

	data := NewZkDocumentData(spec.ID, document.DocType, timestamp, signedItemsOf(items), chain)
	return &ZkDocument{DocumentData: data, Proof: proof}, nil
}

// VerifyProof checks a proof against the cleartext claim it accompanies.
//
// Everything it feeds the verifier comes from the document itself, which is
// attacker-controlled until this returns nil — that is the point. The proof is
// what binds the claimed elements, docType, timestamp and issuer key together;
// a caller may not read any of them as fact before this call succeeds.
//
// What it deliberately does not establish is that the issuer is trusted. The
// proof says some key signed the attestation, not whose key it is; chaining
// msoX5chain to a trusted AP is the same job, done the same way, as for a plain
// presentation, and belongs with the caller that owns the trust model.
func (p *ProverSystem) VerifyProof(
	document ZkDocument,
	spec ZkSystemSpec,
	transcript SessionTranscript,
) error {
	if p == nil || p.system == nil {
		return fmt.Errorf("no zk system")
	}

	circuit, ok := spec.CircuitHash()
	if !ok {
		return fmt.Errorf("zk system spec %q carries no %s", spec.ID, ZkParamCircuitHash)
	}

	keyX, keyY, err := issuerKeyCoordinates(document.DocumentData.MsoX5Chain)
	if err != nil {
		return err
	}

	encodedTranscript, err := cbor.Marshal(transcript)
	if err != nil {
		return fmt.Errorf("encode session transcript for verification: %w", err)
	}

	request := zk.VerificationRequest{
		Circuit:    circuit,
		DocType:    document.DocumentData.DocType,
		IssuerKeyX: keyX,
		IssuerKeyY: keyY,
		Transcript: encodedTranscript,
		Attributes: zkAttributesOfSigned(document.DocumentData.IssuerSigned),
		Timestamp:  document.DocumentData.Timestamp,
		Proof:      document.Proof,
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("verification request for %s: %w", document.DocumentData.DocType, err)
	}
	return p.system.Verify(request)
}

// ============================================================
// ELEMENT ORDERING — the same list on both sides
// ============================================================

// orderedElement is one disclosed element with both faces of it: the namespace
// and identifier, and the element value as the bytes it was signed as.
type orderedElement struct {
	namespace string
	item      ZkSignedItem
}

// rawIssuerSignedItem is IssuerSignedItem with the element value left as bytes.
//
// The value has to survive as CBOR, not as a decoded any that is later
// re-encoded: the circuit proves a statement about these exact bytes, and CBOR
// admits several encodings of one value, so a round trip that does not
// reproduce them turns a valid proof into a verification failure with nothing
// naming the cause. ZkSignedItem.ElementValue is a RawMessage for the same
// reason.
type rawIssuerSignedItem struct {
	DigestID          uint64          `cbor:"digestID"`
	Random            []byte          `cbor:"random"`
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

// orderedElements lists a document's disclosed elements in the order they will
// be proved.
//
// The ordering is the load-bearing part. The native verifier's attribute array
// is positional, so prover and verifier have to build the same list in the same
// order or a sound proof is rejected. Within a namespace that is the wire
// order, which the slice already preserves; across namespaces it cannot be,
// because IssuerSigned.NameSpaces is a Go map and ranging over one is
// deliberately randomised. Sorting the namespace names is what makes the two
// sides agree, and it is why nothing here may be "simplified" into a plain
// range over the map.
func orderedElements(document MDoc) ([]orderedElement, error) {
	namespaces := make([]string, 0, len(document.IssuerSigned.NameSpaces))
	for namespace := range document.IssuerSigned.NameSpaces {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	var elements []orderedElement
	for _, namespace := range namespaces {
		for _, tagged := range document.IssuerSigned.NameSpaces[namespace] {
			item, err := tag24Unwrap[rawIssuerSignedItem](tagged.EncodedItem)
			if err != nil {
				return nil, fmt.Errorf("decode IssuerSignedItem in namespace %q: %w", namespace, err)
			}
			elements = append(elements, orderedElement{
				namespace: namespace,
				item: ZkSignedItem{
					ElementIdentifier: item.ElementIdentifier,
					ElementValue:      item.ElementValue,
				},
			})
		}
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("document %s discloses no elements to prove", document.DocType)
	}
	return elements, nil
}

func zkAttributesOf(elements []orderedElement) []zk.Attribute {
	attributes := make([]zk.Attribute, 0, len(elements))
	for _, element := range elements {
		attributes = append(attributes, zk.Attribute{
			Namespace:  element.namespace,
			Identifier: element.item.ElementIdentifier,
			Value:      element.item.ElementValue,
		})
	}
	return attributes
}

// signedItemsOf groups the ordered elements back into the per-namespace map a
// ZkDocumentData carries. Slice order within each namespace is preserved, which
// is what lets the verifier rebuild the same attribute list.
func signedItemsOf(elements []orderedElement) map[string][]ZkSignedItem {
	items := map[string][]ZkSignedItem{}
	for _, element := range elements {
		items[element.namespace] = append(items[element.namespace], element.item)
	}
	return items
}

// zkAttributesOfSigned rebuilds the prover's attribute list from a received
// document. It sorts namespaces for the same reason orderedElements does, and
// the two must stay in step: this is the verifier's half of that agreement.
func zkAttributesOfSigned(signed map[string][]ZkSignedItem) []zk.Attribute {
	namespaces := make([]string, 0, len(signed))
	for namespace := range signed {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	var attributes []zk.Attribute
	for _, namespace := range namespaces {
		for _, item := range signed[namespace] {
			attributes = append(attributes, zk.Attribute{
				Namespace:  namespace,
				Identifier: item.ElementIdentifier,
				Value:      item.ElementValue,
			})
		}
	}
	return attributes
}

// ============================================================
// ISSUER KEY — what the proof is stated relative to
// ============================================================

// issuerChain parses the certificate chain out of the document's issuerAuth.
func issuerChain(document MDoc) ([]*x509.Certificate, error) {
	message, err := decodeCoseSign1(document.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("decode issuerAuth of %s: %w", document.DocType, err)
	}
	return certificateChainFromHeaders(message.Headers.Unprotected)
}

// issuerKeyCoordinates renders the leaf certificate's P-256 public key the way
// the native ABI reads it: 0x-prefixed hex of each 32-byte big-endian affine
// coordinate.
//
// FillBytes rather than Bytes, because a coordinate with leading zero bytes
// encodes shorter than 32 bytes and the ABI reads a fixed width — a
// one-in-256 chance of a proof over a key nobody holds, which is exactly the
// kind of bug that passes every test until it does not.
func issuerKeyCoordinates(chain []*x509.Certificate) (string, string, error) {
	if len(chain) == 0 {
		return "", "", fmt.Errorf("no issuer certificate chain to take a public key from")
	}
	key, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("issuer certificate public key is %T, not ECDSA", chain[0].PublicKey)
	}
	if key.Curve != elliptic.P256() {
		return "", "", fmt.Errorf("issuer key is on curve %s, and the circuit is stated over P-256",
			key.Curve.Params().Name)
	}
	x := "0x" + hex.EncodeToString(key.X.FillBytes(make([]byte, 32)))
	y := "0x" + hex.EncodeToString(key.Y.FillBytes(make([]byte, 32)))
	return x, y, nil
}
