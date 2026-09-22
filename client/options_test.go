package client

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/zk"
	"github.com/stretchr/testify/require"
)

// fakeZkSystem stands in for the native prover, which lives in a module this
// build does not link — which is the whole point of the option taking zk.System
// rather than a concrete type.
type fakeZkSystem struct{ circuits []zk.Circuit }

func (f *fakeZkSystem) Name() string                          { return mdoc.ZkSystemLongfellowV1 }
func (f *fakeZkSystem) Circuits() []zk.Circuit                { return f.circuits }
func (f *fakeZkSystem) Prove(zk.ProofRequest) ([]byte, error) { return []byte{0x01}, nil }
func (f *fakeZkSystem) Verify(zk.VerificationRequest) error   { return nil }

func avCircuit(attrs int, hash string) zk.Circuit {
	return zk.Circuit{
		System: mdoc.ZkSystemLongfellowV1, Version: 6, NumAttributes: attrs,
		BlockEncHash: 4096, BlockEncSig: 2945, Hash: hash,
	}
}

// A build with no prover is the ordinary one, so the zero-option client must
// carry nothing rather than an empty repository that claims to be a system.
func TestWithoutZkProverThereIsNoRepository(t *testing.T) {
	client := &Client{}
	require.Nil(t, client.zkSystems)

	// And a nil repository answers rather than panicking, which is what routes an
	// AV request to the plain presentation instead of failing it.
	require.Nil(t, client.zkSystems.Lookup(mdoc.ZkSystemLongfellowV1))
	require.Empty(t, client.zkSystems.AllSpecs())
}

func TestWithZkProverRegistersTheSystem(t *testing.T) {
	client := &Client{}
	WithZkProver(&fakeZkSystem{circuits: []zk.Circuit{avCircuit(1, "aa")}})(client)

	require.NotNil(t, client.zkSystems)
	require.NotNil(t, client.zkSystems.Lookup(mdoc.ZkSystemLongfellowV1),
		"the system is registered under its own name")

	specs := client.zkSystems.AllSpecs()
	require.Len(t, specs, 1)
	require.Equal(t, mdoc.ZkSystemLongfellowV1+"_6_1_4096_2945_aa", specs[0].ID,
		"the option wraps the byte-oriented system in the adapter, so specs come out profile-shaped")
}

// Repeatable, because a build may hold more than one system and the option is
// the only way to register any of them.
func TestWithZkProverIsRepeatable(t *testing.T) {
	client := &Client{}
	WithZkProver(&fakeZkSystem{circuits: []zk.Circuit{avCircuit(1, "aa")}})(client)
	WithZkProver(&fakeZkSystem{circuits: []zk.Circuit{avCircuit(2, "bb")}})(client)

	require.Len(t, client.zkSystems.AllSpecs(), 2)
}

// A nil system is a caller mistake that must not become a repository holding a
// nil, which would panic later on a goroutine nobody can recover.
func TestWithZkProverIgnoresNil(t *testing.T) {
	client := &Client{}
	WithZkProver(nil)(client)
	require.Nil(t, client.zkSystems)
}
