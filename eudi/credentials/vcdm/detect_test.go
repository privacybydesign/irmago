package vcdm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	vcdmDoc := docFromJSON(t, exampleAlumniCredential)
	require.Equal(t, DataModelVCDM, Detect(vcdmDoc))
	require.True(t, IsVCDM(vcdmDoc))

	// An IETF SD-JWT VC: a `vct` type claim, no VCDM `@context`/`type`.
	sdJwtVc := docFromJSON(t, `{
		"vct": "https://example.com/credentials/identity",
		"iss": "https://issuer.example",
		"given_name": "Alice"}`)
	require.Equal(t, DataModelSdJwtVc, Detect(sdJwtVc))
	require.False(t, IsVCDM(sdJwtVc))

	// Neither data model.
	plain := docFromJSON(t, `{"iss": "https://issuer.example", "foo": "bar"}`)
	require.Equal(t, DataModelUnknown, Detect(plain))
	require.False(t, IsVCDM(plain))
}

func TestIsVCDM_RequiresBaseContextFirst(t *testing.T) {
	// VCDM base context present but not first: not VCDM.
	notFirst := docFromJSON(t, `{
		"@context": ["https://example.com/ctx", "https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential"]}`)
	require.False(t, IsVCDM(notFirst))

	// Base context first but type omits VerifiableCredential: not VCDM.
	wrongType := docFromJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["SomethingElse"]}`)
	require.False(t, IsVCDM(wrongType))
}
