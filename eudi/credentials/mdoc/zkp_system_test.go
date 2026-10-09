package mdoc

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeZkSystem stands in for the native prover, which lives in a module this
// one does not link. It records whether VerifyProof was reached, which is what
// the A.8 ordering test turns on: a rejected circuit must never get that far.
type fakeZkSystem struct {
	name           string
	specs          []ZkSystemSpec
	verifyCalled   bool
	verifyErr      error
	generateCalled bool
}

func (f *fakeZkSystem) Name() string { return f.name }

func (f *fakeZkSystem) SystemSpecs() []ZkSystemSpec { return f.specs }

func (f *fakeZkSystem) MatchingSpec(offered []ZkSystemSpec, numAttributes int) (ZkSystemSpec, bool) {
	for _, mine := range f.specs {
		count, ok := mine.NumAttributes()
		if !ok || count != int64(numAttributes) {
			continue
		}
		if slices.ContainsFunc(offered, mine.SameCircuit) {
			return mine, true
		}
	}
	return ZkSystemSpec{}, false
}

func (f *fakeZkSystem) GenerateProof(
	spec ZkSystemSpec, document MDoc, transcript SessionTranscript, timestamp time.Time,
) (*ZkDocument, error) {
	f.generateCalled = true
	return &ZkDocument{
		DocumentData: NewZkDocumentData(spec.ID, document.DocType, timestamp, nil, nil),
		Proof:        []byte{0x01},
	}, nil
}

func (f *fakeZkSystem) VerifyProof(document ZkDocument, spec ZkSystemSpec, transcript SessionTranscript) error {
	f.verifyCalled = true
	return f.verifyErr
}

func acceptedTestCircuits() *AcceptedCircuits {
	hash, _ := zkTestSpec().CircuitHash()
	return NewAcceptedCircuits(hash)
}

// TestZkSystemRepositoryIsNilSafe pins the decision that a build without the
// native prover is an ordinary build, not a broken one: A.8's fallback only
// works if absence routes to "no proof available" rather than to an error.
func TestZkSystemRepositoryIsNilSafe(t *testing.T) {
	var repository *ZkSystemRepository

	require.Nil(t, repository.Lookup(ZkSystemLongfellowV1))
	require.Empty(t, repository.AllSpecs())

	_, found := repository.SpecByID("anything")
	require.False(t, found)

	_, _, ok := repository.SelectProver(ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}}, 1)
	require.False(t, ok)
}

func TestZkSystemRepositoryLookupAndSpecs(t *testing.T) {
	system := &fakeZkSystem{name: ZkSystemLongfellowV1, specs: []ZkSystemSpec{zkTestSpec()}}
	repository := NewZkSystemRepository(system)

	require.Same(t, system, repository.Lookup(ZkSystemLongfellowV1))
	require.Nil(t, repository.Lookup("some-other-zk-system"))
	require.Len(t, repository.AllSpecs(), 1)

	spec, found := repository.SpecByID(zkTestSpec().ID)
	require.True(t, found)
	require.Equal(t, zkTestSpec().ID, spec.ID)

	_, found = repository.SpecByID("a label this verifier never minted")
	require.False(t, found)
}

func TestSelectProver(t *testing.T) {
	repository := NewZkSystemRepository(
		&fakeZkSystem{name: ZkSystemLongfellowV1, specs: []ZkSystemSpec{zkTestSpec()}},
	)

	t.Run("reader and wallet share a circuit", func(t *testing.T) {
		system, spec, ok := repository.SelectProver(
			ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}}, 1)
		require.True(t, ok)
		require.Equal(t, ZkSystemLongfellowV1, system.Name())
		require.Equal(t, zkTestSpec().ID, spec.ID)
	})

	t.Run("reader offers a circuit we do not hold", func(t *testing.T) {
		theirs := zkTestSpec()
		theirs.Params[ZkParamCircuitHash] = "0000000000000000000000000000000000000000000000000000000000000000"

		_, _, ok := repository.SelectProver(ZkRequest{SystemSpecs: []ZkSystemSpec{theirs}}, 1)
		require.False(t, ok)
	})

	t.Run("reader offers a system we do not have", func(t *testing.T) {
		theirs := zkTestSpec()
		theirs.System = "some-future-zk-system"

		_, _, ok := repository.SelectProver(ZkRequest{SystemSpecs: []ZkSystemSpec{theirs}}, 1)
		require.False(t, ok)
	})

	// A circuit proves a fixed number of statements, so a request for more
	// elements than the circuit was built for has no answer under it.
	t.Run("more elements than the circuit is built for", func(t *testing.T) {
		_, _, ok := repository.SelectProver(ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}}, 4)
		require.False(t, ok)
	})
}

func TestAcceptedCircuits(t *testing.T) {
	spec := zkTestSpec()

	t.Run("a published circuit is accepted", func(t *testing.T) {
		require.NoError(t, acceptedTestCircuits().Accepts(spec))
	})

	t.Run("an unpublished circuit is rejected", func(t *testing.T) {
		other := zkTestSpec()
		other.Params[ZkParamCircuitHash] = "0000000000000000000000000000000000000000000000000000000000000000"
		require.ErrorContains(t, acceptedTestCircuits().Accepts(other), "not in the accepted circuit set")
	})

	// Failing closed is the deliberate reading of A.8 for a verifier that has
	// not been told what the scheme owner accepts: with no list loaded there is
	// no circuit it can attest is accepted, and the plain A.6 presentation
	// still gets the session through.
	t.Run("no configured set accepts nothing", func(t *testing.T) {
		var unset *AcceptedCircuits
		require.ErrorContains(t, unset.Accepts(spec), "no accepted circuit set is configured")
		require.ErrorContains(t, NewAcceptedCircuits().Accepts(spec), "no accepted circuit set is configured")
	})

	t.Run("a spec with no circuit hash is rejected", func(t *testing.T) {
		bare := ZkSystemSpec{ID: "bare", System: ZkSystemLongfellowV1}
		require.ErrorContains(t, acceptedTestCircuits().Accepts(bare), ZkParamCircuitHash)
	})
}

// TestVerifyZkDocumentChecksCircuitBeforeVerifying is the test the whole
// AcceptedCircuits type exists for. A.8: "An RP SHALL verify that the
// Zero-Knowledge Proof was generated using an accepted circuit [...] before
// verifying the proof." Checking afterwards would be sound arithmetic and an
// unsound policy — a proof under a withdrawn circuit verifies perfectly well,
// so the hash check is the only thing keeping it out.
func TestVerifyZkDocumentChecksCircuitBeforeVerifying(t *testing.T) {
	withdrawn := zkTestSpec()
	withdrawn.ID = "withdrawn-circuit"
	withdrawn.Params[ZkParamCircuitHash] = "0000000000000000000000000000000000000000000000000000000000000000"

	system := &fakeZkSystem{name: ZkSystemLongfellowV1, specs: []ZkSystemSpec{withdrawn}}
	repository := NewZkSystemRepository(system)

	document := ZkDocument{
		DocumentData: NewZkDocumentData(withdrawn.ID, "eu.europa.ec.av.1", time.Now(), nil, nil),
		Proof:        []byte{0x01},
	}

	_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, document.DocumentData.Timestamp)
	require.ErrorContains(t, err, "not in the accepted circuit set")
	require.False(t, system.verifyCalled, "the proof must not be verified under an unaccepted circuit")
}

func TestVerifyZkDocument(t *testing.T) {
	newFixture := func() (*fakeZkSystem, *ZkSystemRepository, ZkDocument) {
		system := &fakeZkSystem{name: ZkSystemLongfellowV1, specs: []ZkSystemSpec{zkTestSpec()}}
		document := ZkDocument{
			DocumentData: NewZkDocumentData(zkTestSpec().ID, "eu.europa.ec.av.1", time.Now(), nil, nil),
			Proof:        []byte{0x01},
		}
		return system, NewZkSystemRepository(system), document
	}

	t.Run("accepted circuit and valid proof", func(t *testing.T) {
		system, repository, document := newFixture()

		spec, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, document.DocumentData.Timestamp)
		require.NoError(t, err)
		require.Equal(t, zkTestSpec().ID, spec.ID)
		require.True(t, system.verifyCalled)
	})

	t.Run("an invalid proof is an error", func(t *testing.T) {
		system, repository, document := newFixture()
		system.verifyErr = fmt.Errorf("MDOC_VERIFIER_GENERAL_FAILURE")

		_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, document.DocumentData.Timestamp)
		require.ErrorContains(t, err, "zk proof verification failed")
	})

	// The identifier is the wallet's own label and carries no authority: one
	// the verifier never minted selects no circuit, and the presentation is
	// refused rather than the verifier going looking elsewhere for one.
	t.Run("an unknown spec identifier is refused", func(t *testing.T) {
		system, repository, document := newFixture()
		document.DocumentData.ZkSystemSpecID = "a label this verifier never minted"

		_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, document.DocumentData.Timestamp)
		require.ErrorContains(t, err, "unknown zk system spec")
		require.False(t, system.verifyCalled)
	})

	t.Run("a build without the prover cannot verify", func(t *testing.T) {
		_, _, document := newFixture()

		_, err := VerifyZkDocument(document, nil, acceptedTestCircuits(), SessionTranscript{}, document.DocumentData.Timestamp)
		require.ErrorContains(t, err, "unknown zk system spec")
	})
}

// TestVerifyZkDocumentChecksTheTimestamp: the instant the proof asserts has to
// be the verifier's own, within tolerance.
//
// This is what makes A.8's fourth statement -- "the Proof of Age attestation is
// within its validity period" -- mean anything. The circuit proves that against
// the timestamp the WALLET supplies, so a holder whose attestation expired last
// month can generate a fresh, entirely sound proof today asserting a date from
// when it was still valid, and every cryptographic check passes. The timestamp
// is an input the prover controls, not a record of when the proof was made.
func TestVerifyZkDocumentChecksTheTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	documentAt := func(asserted time.Time) (*fakeZkSystem, *ZkSystemRepository, ZkDocument) {
		system := &fakeZkSystem{name: ZkSystemLongfellowV1, specs: []ZkSystemSpec{zkTestSpec()}}
		document := ZkDocument{
			DocumentData: NewZkDocumentData(zkTestSpec().ID, "eu.europa.ec.av.1", asserted, nil, nil),
			Proof:        []byte{0x01},
		}
		return system, NewZkSystemRepository(system), document
	}

	t.Run("a stale timestamp is refused before the proof is verified", func(t *testing.T) {
		// The attack: a proof made now, asserting an instant when the credential
		// was still valid.
		system, repository, document := documentAt(now.Add(-30 * 24 * time.Hour))

		_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, now)
		require.ErrorContains(t, err, "outside the")
		require.False(t, system.verifyCalled,
			"refused on the cheap check: verifying the proof would say nothing about this")
	})

	t.Run("a timestamp far in the future is refused", func(t *testing.T) {
		_, repository, document := documentAt(now.Add(24 * time.Hour))

		_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, now)
		require.ErrorContains(t, err, "outside the")
	})

	t.Run("ordinary clock skew and proving time are accepted", func(t *testing.T) {
		for _, offset := range []time.Duration{
			0,
			-10 * time.Second, // proof generation plus transport
			-ZkTimestampTolerance + time.Second,
			ZkTimestampTolerance - time.Second, // the reader's clock lags
		} {
			_, repository, document := documentAt(now.Add(offset))

			_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, now)
			require.NoError(t, err, "offset %s must be accepted", offset)
		}
	})

	t.Run("no timestamp at all is refused", func(t *testing.T) {
		_, repository, document := documentAt(time.Time{})

		_, err := VerifyZkDocument(document, repository, acceptedTestCircuits(), SessionTranscript{}, now)
		require.ErrorContains(t, err, "asserts no timestamp")
	})
}
