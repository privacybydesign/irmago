package mdoc

import (
	"fmt"
	"time"
)

// ============================================================
// ZK SYSTEMS — the seam the native prover arrives through
// ============================================================
//
// Nothing in this module produces or checks a zero-knowledge proof. The one
// system in scope, longfellow-libzk-v1, exists as a C++ library, and irmago
// deliberately does not compile C++: `./yivi` has to cross-build with
// CGO_ENABLED=0, an ordinary `go build` must not demand a ZK toolchain, and the
// F-Droid build of the wallet has to be buildable from source. So the native
// code lives in a module of its own and reaches this package as an
// implementation of ZkSystem.
//
// The consequence to keep in mind everywhere downstream: a nil ZkSystemRepository
// is not an error, it is the ordinary state of a build without the prover. A.8
// plans for exactly this — "where the User's device does not support
// Zero-Knowledge Proof generation, the AVI SHALL fall back to the plain ISO
// mDoc presentation defined in Section A.6" — so absence has to route to the
// fallback, never to a failed session. Every method here is nil-safe for that
// reason.

// ZkSystem is one zero-knowledge proof system: the circuits it holds, and the
// ability to prove and check statements under them.
//
// An implementation is expected to be cheap to consult and expensive to run.
// SystemSpecs and MatchingSpec answer from circuits already loaded, and are
// called while deciding what to offer or whether a fallback is needed;
// GenerateProof is the part that takes seconds and hundreds of megabytes.
type ZkSystem interface {
	// Name is the system identifier that appears in a ZkSystemSpec's System
	// field — ZkSystemLongfellowV1 for anything in scope for this profile.
	Name() string

	// SystemSpecs lists every circuit this system can prove and verify with.
	// A verifier offers these to the wallet; a wallet matches the verifier's
	// offer against them.
	//
	// Implementations must not take a circuit's identity on trust. A spec's
	// circuit_hash is computable from the circuit itself — longfellow's
	// circuit_id parses the bytes into their two circuits, takes each one's id
	// and hashes the pair — so an implementation that loads circuits from files
	// must recompute it and refuse any circuit whose bytes disagree with the
	// hash it is filed under.
	//
	// This is load-time work, once per circuit rather than once per proof, and
	// skipping it is not merely untidy: it is what AcceptedCircuits rests on.
	// See the note there. Multipaz's addCircuit is the cautionary case — it
	// parses the claimed hash out of the circuit's filename and stores it
	// beside the bytes with nothing checking that the two correspond.
	SystemSpecs() []ZkSystemSpec

	// MatchingSpec picks the circuit to answer a request with: one that the
	// reader offered, that this system holds, and that is built for exactly
	// numAttributes attributes. Where several qualify the newest version wins.
	// The bool is false when the reader and the wallet have no circuit in
	// common, which is a fallback, not a failure — see ZkRequest.ZkRequired.
	MatchingSpec(offered []ZkSystemSpec, numAttributes int) (ZkSystemSpec, bool)

	// GenerateProof proves the statements of A.8 about document, which must
	// already carry its DeviceSigned: the proof covers the device signature
	// over this session's transcript, so the ordinary presentation path runs
	// first and unchanged, and only then is the result proved instead of sent.
	GenerateProof(spec ZkSystemSpec, document MDoc, transcript SessionTranscript, timestamp time.Time) (*ZkDocument, error)

	// VerifyProof checks a proof against the cleartext claim it accompanies.
	// It establishes the four A.8 statements and nothing else — in particular
	// it says nothing about whether the issuer in msoX5chain is trusted, which
	// stays with the ordinary trust model.
	VerifyProof(document ZkDocument, spec ZkSystemSpec, transcript SessionTranscript) error
}

// ZkSystemRepository holds the ZK systems a build has. A nil repository is a
// build with none; every method tolerates it.
type ZkSystemRepository struct {
	systems []ZkSystem
}

// NewZkSystemRepository returns a repository over the given systems.
func NewZkSystemRepository(systems ...ZkSystem) *ZkSystemRepository {
	return &ZkSystemRepository{systems: systems}
}

// Add registers a system and returns the repository, so registrations chain.
func (r *ZkSystemRepository) Add(system ZkSystem) *ZkSystemRepository {
	r.systems = append(r.systems, system)
	return r
}

// Lookup finds a registered system by name, or nil.
func (r *ZkSystemRepository) Lookup(name string) ZkSystem {
	if r == nil {
		return nil
	}
	for _, system := range r.systems {
		if system.Name() == name {
			return system
		}
	}
	return nil
}

// AllSpecs lists every circuit every registered system holds. This is what a
// verifier puts in the ZkRequest it sends, and what it later resolves a
// returned zkSystemId against.
func (r *ZkSystemRepository) AllSpecs() []ZkSystemSpec {
	if r == nil {
		return nil
	}
	var specs []ZkSystemSpec
	for _, system := range r.systems {
		specs = append(specs, system.SystemSpecs()...)
	}
	return specs
}

// SpecByID finds a spec by the identifier a wallet echoed back in a
// ZkDocument. Resolution is by lookup among the verifier's own specs rather
// than by parsing the identifier, because the identifier is the wallet's label
// and carries no authority: it selects which circuit to load, and a circuit is
// only ever loaded from the verifier's own set.
func (r *ZkSystemRepository) SpecByID(id string) (ZkSystemSpec, bool) {
	for _, spec := range r.AllSpecs() {
		if spec.ID == id {
			return spec, true
		}
	}
	return ZkSystemSpec{}, false
}

// SelectProver answers the wallet-side question: given what this reader will
// accept and how many elements are about to be disclosed, is there a proof we
// can produce?
//
// A false return is the fallback path of A.8 and covers every way a build can
// come up short — no prover compiled in, the reader offering only circuits we
// do not hold, or a request for more elements than any circuit we hold is built
// for. The caller decides what to do with that, and the decision is
// ZkRequest.ZkRequired's: fall back to a plain A.6 presentation when the reader
// left it optional, fail the session when it did not.
func (r *ZkSystemRepository) SelectProver(request ZkRequest, numAttributes int) (ZkSystem, ZkSystemSpec, bool) {
	if r == nil {
		return nil, ZkSystemSpec{}, false
	}
	for _, offered := range request.SystemSpecs {
		system := r.Lookup(offered.System)
		if system == nil {
			continue
		}
		spec, ok := system.MatchingSpec(request.SystemSpecs, numAttributes)
		if ok {
			return system, spec, true
		}
	}
	return nil, ZkSystemSpec{}, false
}

// ============================================================
// ACCEPTED CIRCUITS — the relying party's gate
// ============================================================

// AcceptedCircuits is the set of circuits a relying party will verify proofs
// under, identified by circuit hash.
//
// A.8 makes this a requirement rather than a configuration nicety: "An RP SHALL
// verify that the Zero-Knowledge Proof was generated using an accepted circuit,
// by verifying the circuit hash against the set of circuits accepted for the
// purposes of this profile, before verifying the proof. An RP SHALL reject a
// presentation generated using a circuit that is not among the accepted
// circuits." The set itself "is published and maintained by the scheme owner
// separately from this document", which is why this type is constructed from
// configuration rather than compiled in.
//
// The ordering the clause imposes is the interesting part. Verifying first and
// checking the hash after would be sound arithmetic and an unsound policy: a
// proof under a withdrawn circuit verifies perfectly well, so the hash check is
// the only thing standing between a revoked or weakened circuit and an accepted
// presentation. VerifyZkDocument exists so a caller cannot get that order
// wrong by accident.
//
// The precondition this type rests on, which it cannot check itself: the hash
// compared here identifies a circuit only if the ZkSystem's spec is honestly
// bound to the circuit the system will actually verify under. Nothing in this
// package establishes that binding — it is made when circuits are loaded, and
// the ZkSystem implementation owns it. An implementation that files a circuit
// under a hash it never recomputed turns this whole check into theatre: the
// presentation passes the accepted-circuit gate and the proof is then verified
// against a circuit no scheme owner approved. See the note on
// ZkSystem.SystemSpecs for what a loader has to do about it.
type AcceptedCircuits struct {
	hashes map[string]struct{}
}

// NewAcceptedCircuits builds the accepted set from the scheme owner's published
// circuit hashes.
func NewAcceptedCircuits(hashes ...string) *AcceptedCircuits {
	set := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		set[hash] = struct{}{}
	}
	return &AcceptedCircuits{hashes: set}
}

// Accepts reports whether a spec names a circuit in the accepted set.
//
// A nil AcceptedCircuits accepts nothing, and an empty one likewise. That is
// the deliberate reading of "reject a presentation generated using a circuit
// that is not among the accepted circuits" for a verifier that has not been
// told what the set is: with no published list loaded, there is no circuit it
// can attest is accepted. Failing closed here costs a deployment the ZK path
// until it is configured — and the plain A.6 presentation, which every RP must
// accept anyway, still gets the session through.
func (a *AcceptedCircuits) Accepts(spec ZkSystemSpec) error {
	hash, ok := spec.CircuitHash()
	if !ok || hash == "" {
		return fmt.Errorf("zk system spec %q carries no %s", spec.ID, ZkParamCircuitHash)
	}
	if a == nil || len(a.hashes) == 0 {
		return fmt.Errorf(
			"no accepted circuit set is configured, so circuit %s cannot be accepted", hash)
	}
	if _, accepted := a.hashes[hash]; !accepted {
		return fmt.Errorf("circuit %s is not in the accepted circuit set", hash)
	}
	return nil
}

// VerifyZkDocument is the relying party's entry point for a ZK presentation. It
// performs, in the order A.8 requires:
//
//  1. resolve the circuit the wallet says it used against the verifier's own
//     specs — an identifier the verifier does not know is a rejection, not a
//     reason to go looking for a circuit elsewhere;
//  2. check that circuit's hash against the accepted set;
//  3. only then verify the proof.
//
// It returns the resolved spec so a caller can record which circuit a
// presentation was accepted under.
//
// What it deliberately does not do is decide whether the issuer is trusted.
// The proof establishes that some key signed the attestation, not whose key it
// is; establishing that msoX5chain chains to a trusted AP is the same job, done
// the same way, as for a plain presentation, and it belongs with the caller
// that owns the trust model.
func VerifyZkDocument(
	document ZkDocument,
	repository *ZkSystemRepository,
	accepted *AcceptedCircuits,
	transcript SessionTranscript,
) (ZkSystemSpec, error) {
	specID := document.DocumentData.ZkSystemSpecID

	spec, found := repository.SpecByID(specID)
	if !found {
		return ZkSystemSpec{}, fmt.Errorf("unknown zk system spec %q", specID)
	}

	if err := accepted.Accepts(spec); err != nil {
		return ZkSystemSpec{}, fmt.Errorf("refusing proof under spec %q: %w", specID, err)
	}

	system := repository.Lookup(spec.System)
	if system == nil {
		return ZkSystemSpec{}, fmt.Errorf("no zk system registered for %q", spec.System)
	}

	if err := system.VerifyProof(document, spec, transcript); err != nil {
		return ZkSystemSpec{}, fmt.Errorf("zk proof verification failed: %w", err)
	}
	return spec, nil
}
