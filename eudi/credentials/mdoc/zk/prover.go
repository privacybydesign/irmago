// Package zk is the module boundary the native zero-knowledge prover arrives
// through: bytes in, bytes out, and nothing else.
//
// # Why this package imports only the standard library
//
// The one ZK system in scope, longfellow-libzk-v1, is a C++ library. irmago
// deliberately does not compile C++ — ./yivi cross-builds with CGO_ENABLED=0,
// an ordinary go build must not demand a ZK toolchain, and the F-Droid build of
// the wallet has to be buildable from source — so the cgo binding lives in a
// module of its own.
//
// That module implements the interfaces declared here. For it to do so without
// dragging irmago into its own build, the types crossing the boundary have to
// be types it can name cheaply: byte slices, strings, and time.Time. If this
// package took an mdoc.MDoc or a dcql.DisclosureSelection, the prover module
// would have to import all of irmago to satisfy one interface, and the split
// that keeps C++ out of irmago's build would collapse into a mutual dependency.
//
// The direction of the dependency is the other half of it. irmago never imports
// the prover module; the prover module imports this package. Wiring the two
// together is the application's job — it is the only component with reason to
// want both. That is why a build with no prover is the ordinary state rather
// than an error, and why AV Annex A §A.8 plans for it: "where the User's device
// does not support Zero-Knowledge Proof generation, the AVI SHALL fall back to
// the plain ISO mDoc presentation defined in Section A.6."
//
// # What this package deliberately does not know
//
// Nothing here understands mdoc, CBOR, the AV profile, or how a circuit is
// chosen. Callers hand over encoded bytes they have already produced and get a
// proof back. The adapter that speaks both languages is mdoc.ProverSystem,
// which implements mdoc.ZkSystem over a System declared here.
package zk

import (
	"errors"
	"fmt"
	"time"
)

// TimestampFormat is how the native ABI wants an instant: exactly twenty
// characters, whole seconds, a literal trailing Z.
//
// It is not time.RFC3339, which renders a numeric zone, and it has no
// fractional part, because the C interface reads a fixed twenty-byte field —
// "2023-11-02T09:00:00Z". A timestamp that formats to any other length is not a
// slightly wrong input; it is a different statement about validity than the one
// the caller meant.
const TimestampFormat = "2006-01-02T15:04:05Z"

// TimestampLen is the width the native ABI reads. Declared next to the format
// so a test can assert the two agree: a format string and a length that drift
// apart silently produce a proof over the wrong instant.
const TimestampLen = 20

// FormatTimestamp renders an instant the way the prover reads it: UTC, and
// truncated to the whole second the proof will actually be about.
//
// Truncating here rather than at the call site means the value a caller records
// alongside the proof and the value the proof was taken over cannot disagree.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(TimestampFormat)
}

// The fixed field widths of the native RequestedAttribute struct. These are a
// property of the C ABI, not a policy this package invents, and they are
// declared here because this is the last place a caller can be told about them
// before the bytes cross into C.
const (
	MaxNamespaceLen  = 64
	MaxIdentifierLen = 32
	MaxValueLen      = 64
)

// ErrNoCircuit is returned when a request names a circuit the implementation
// does not hold. It is a distinct error because it is the one failure that is
// legitimately a fallback rather than a fault: a wallet and a reader with no
// circuit in common is the ordinary outcome that §A.8 sends down the plain
// presentation path.
var ErrNoCircuit = errors.New("no such circuit")

// Attribute is one data element the proof opens: named, and stated in the clear
// alongside the proof that it is what the issuer signed.
type Attribute struct {
	// Namespace is the mdoc namespace the element lives in, e.g.
	// "org.iso.18013.5.1".
	Namespace string

	// Identifier is the data element identifier, e.g. "age_over_18".
	Identifier string

	// Value is the element value as encoded CBOR, verbatim — the bytes as they
	// appear inside the issuer-signed item, not a re-encoding of a decoded
	// value.
	//
	// This matters more than it looks. CBOR admits several encodings of one
	// value: a tagged date, an integer whose width depends on its magnitude. The
	// circuit proves a statement about these exact bytes, so a round trip that
	// does not reproduce them turns a valid proof into a verification failure
	// with nothing naming the cause.
	Value []byte
}

// Validate reports whether an attribute fits the fixed widths of the native
// struct.
//
// It refuses over-long input rather than truncating it. Google's own
// set_attribute in reference/verifier-service clamps cbor_value to 64 bytes
// silently, which would prove a statement about a different value than the one
// asked for — the wrong failure mode for a credential, because the resulting
// proof is perfectly valid about something nobody requested.
func (a Attribute) Validate() error {
	switch {
	case a.Namespace == "":
		return errors.New("attribute namespace is empty")
	case a.Identifier == "":
		return errors.New("attribute identifier is empty")
	case len(a.Value) == 0:
		return fmt.Errorf("attribute %s/%s has no value", a.Namespace, a.Identifier)
	case len(a.Namespace) > MaxNamespaceLen:
		return fmt.Errorf("attribute namespace %q is %d bytes, the limit is %d",
			a.Namespace, len(a.Namespace), MaxNamespaceLen)
	case len(a.Identifier) > MaxIdentifierLen:
		return fmt.Errorf("attribute identifier %q is %d bytes, the limit is %d",
			a.Identifier, len(a.Identifier), MaxIdentifierLen)
	case len(a.Value) > MaxValueLen:
		return fmt.Errorf("attribute %s/%s has a %d byte value, the limit is %d",
			a.Namespace, a.Identifier, len(a.Value), MaxValueLen)
	}
	return nil
}

// Circuit describes one circuit an implementation holds and will prove or
// verify under.
//
// An implementation must not report a circuit whose Hash it has taken on trust.
// The hash is computable from the circuit bytes — longfellow's circuit_id parses
// them into their two circuits, takes each one's id and hashes the pair — so a
// loader must recompute it and refuse any circuit whose bytes disagree with the
// hash it is filed under. Everything downstream rests on that: the relying
// party's accepted-circuit gate compares this hash, and a circuit filed under a
// hash nobody recomputed turns that check into theatre.
//
// Multipaz's addCircuit is the cautionary case — it parses the claimed hash out
// of the circuit's filename and stores it beside the bytes with nothing checking
// that the two correspond.
type Circuit struct {
	// System is the ZK system name, e.g. "longfellow-libzk-v1".
	System string

	// Version is the ZK specification version the circuit was built for.
	Version int

	// NumAttributes is how many data elements the circuit opens. A circuit
	// proves a fixed number of statements, so a request for three elements
	// cannot be answered by a two-attribute circuit.
	NumAttributes int

	// BlockEncHash and BlockEncSig are the circuit's block-encoding parameters.
	// They are part of what a circuit is rather than tuning knobs, which is why
	// they travel with it: the AV profile's circuit identifier is built from
	// them, so a caller that does not carry them cannot name the circuit it is
	// holding.
	BlockEncHash int
	BlockEncSig  int

	// Hash identifies the circuit: lowercase hex of longfellow's circuit_id.
	Hash string
}

// ProofRequest is everything the prover needs to produce a proof. Every field
// is already encoded; this package does no CBOR.
type ProofRequest struct {
	// Circuit is the Hash of the circuit to prove under. Naming the circuit by
	// its hash rather than by an index or a label means a caller cannot select
	// one circuit and believe it selected another.
	Circuit string

	// DocType is the mdoc docType the presentation is of.
	DocType string

	// DeviceResponse is the CBOR of a DeviceResponse carrying the document to
	// prove over, with its deviceSigned attached.
	//
	// A DeviceResponse, not a bare document: the native prover expects
	// DeviceResponse CBOR and takes the first document in it.
	//
	// The deviceSigned is not optional. The prover refuses a document without
	// one — MDOC_PROVER_DEVICE_SIGNED_MISSING — because one of §A.8's four
	// statements is that the wallet can produce a signature over the session's
	// nonce verifiable under the key in the attestation, and there is nothing to
	// prove without it. So the ordinary presentation path runs first, unchanged,
	// and the proof is taken over its result rather than instead of it.
	DeviceResponse []byte

	// IssuerKeyX and IssuerKeyY are the issuer signing key's P-256 affine
	// coordinates, as 0x-prefixed hex of the 32-byte big-endian value.
	//
	// The proof is stated relative to this key: it establishes that some key
	// signed the attestation, not whose key it is. Deciding that the key belongs
	// to a trusted issuer is a separate job, done through the ordinary trust
	// model, and this package has no opinion on it.
	IssuerKeyX string
	IssuerKeyY string

	// Transcript is the encoded SessionTranscript the proof binds to. It is what
	// stops a proof produced for one session being replayed into another.
	Transcript []byte

	// Attributes are the elements the proof opens, in the order they are to be
	// proved. Order is significant: the native verifier's attribute array is
	// positional, so a verifier that rebuilds this list in another order will
	// reject a sound proof.
	Attributes []Attribute

	// Timestamp is the instant the validity-period statement is proved against —
	// §A.8's fourth statement, "the Proof of Age attestation is within its
	// validity period". It is an input to the circuit, not a note about when
	// this ran.
	Timestamp time.Time
}

// Validate checks a request for the faults this package can see without a
// circuit: the ones that would otherwise surface as an opaque native error code
// several layers down.
func (r ProofRequest) Validate() error {
	switch {
	case r.Circuit == "":
		return errors.New("proof request names no circuit")
	case r.DocType == "":
		return errors.New("proof request has no docType")
	case len(r.DeviceResponse) == 0:
		return errors.New("proof request carries no DeviceResponse")
	case len(r.Transcript) == 0:
		return errors.New("proof request carries no session transcript")
	case len(r.Attributes) == 0:
		return errors.New("proof request opens no attributes")
	}
	if err := validateKey(r.IssuerKeyX, r.IssuerKeyY); err != nil {
		return err
	}
	return validateAttributes(r.Attributes)
}

// VerificationRequest is everything needed to check a proof. It is deliberately
// not a ProofRequest with the document swapped out: a verifier never sees the
// DeviceResponse, which is the whole point of the exercise.
type VerificationRequest struct {
	// Circuit is the Hash of the circuit the proof claims to have been produced
	// under.
	//
	// A caller must resolve this against circuits it already accepts before
	// calling. §A.8 requires the accepted-circuit check to happen before
	// verification, because a proof under a withdrawn circuit verifies perfectly
	// well and the hash check is the only thing standing between a revoked
	// circuit and an accepted presentation.
	Circuit string

	DocType string

	IssuerKeyX string
	IssuerKeyY string

	Transcript []byte

	// Attributes are the cleartext claims the proof is checked against, in the
	// order they were proved.
	Attributes []Attribute

	Timestamp time.Time

	// Proof is the opaque proof blob the prover produced.
	Proof []byte
}

// Validate checks a verification request for locally visible faults.
func (r VerificationRequest) Validate() error {
	switch {
	case r.Circuit == "":
		return errors.New("verification request names no circuit")
	case r.DocType == "":
		return errors.New("verification request has no docType")
	case len(r.Transcript) == 0:
		return errors.New("verification request carries no session transcript")
	case len(r.Proof) == 0:
		return errors.New("verification request carries no proof")
	case len(r.Attributes) == 0:
		return errors.New("verification request opens no attributes")
	}
	if err := validateKey(r.IssuerKeyX, r.IssuerKeyY); err != nil {
		return err
	}
	return validateAttributes(r.Attributes)
}

func validateAttributes(attributes []Attribute) error {
	for i, attribute := range attributes {
		if err := attribute.Validate(); err != nil {
			return fmt.Errorf("attribute %d: %w", i, err)
		}
	}
	return nil
}

// validateKey checks only that the coordinates are present and the right shape.
// It does not check that the point is on the curve: that is the native side's
// job, and a caller that parsed a certificate to get here already has a point.
func validateKey(x, y string) error {
	for _, coordinate := range []struct {
		name  string
		value string
	}{{"x", x}, {"y", y}} {
		if coordinate.value == "" {
			return fmt.Errorf("no issuer key %s coordinate", coordinate.name)
		}
		// "0x" plus 64 hex characters for a 32-byte P-256 coordinate.
		if len(coordinate.value) != 66 || coordinate.value[:2] != "0x" {
			return fmt.Errorf("issuer key %s coordinate %q is not 0x-prefixed 32-byte hex",
				coordinate.name, coordinate.value)
		}
	}
	return nil
}

// Prover produces proofs. Split from Verifier because the two are separately
// useful: a relying party's build needs to check proofs and has no reason to
// carry the ability to make them.
type Prover interface {
	// Prove produces a proof for the request, or an error. ErrNoCircuit means
	// the named circuit is not held, which is a fallback rather than a fault.
	//
	// This is the expensive call: seconds of CPU, and on the order of 150 MB
	// resident against the current library. Implementations are expected to be
	// used from one goroutine at a time.
	Prove(request ProofRequest) ([]byte, error)
}

// Verifier checks proofs.
type Verifier interface {
	// Verify returns nil when the proof establishes the requested statements
	// about the given attributes, under the named circuit and bound to the given
	// transcript. Any other return means the presentation must be refused.
	Verify(request VerificationRequest) error
}

// System is one complete zero-knowledge system: what it can do, and the
// circuits it can do it under.
//
// Cheap to consult, expensive to run — Name and Circuits answer from what is
// already loaded and are called while deciding what to offer or whether a
// fallback is needed, while Prove is the part that takes seconds.
type System interface {
	// Name is the system identifier, e.g. "longfellow-libzk-v1".
	Name() string

	// Circuits lists every circuit this system holds, each with a hash the
	// implementation recomputed from the circuit bytes rather than took on
	// trust. See Circuit.
	Circuits() []Circuit

	Prover
	Verifier
}
