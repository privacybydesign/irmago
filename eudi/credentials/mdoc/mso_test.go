package mdoc

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMSOParserWithVectors is transpiled from multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/mso/MobileSecurityObjectParserTest.kt
//	  -> testMSOParserWithVectors()
//
// It takes the ISO 18013-5 Annex D mdoc response, extracts the MobileSecurityObject
// (the tag-24-wrapped CBOR payload of the issuerAuth COSE_Sign1) and asserts every
// expected field value. The expected values are drawn from ISO 18013-5 Annex D.4.1.2.
func TestMSOParserWithVectors(t *testing.T) {
	deviceResponse, err := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE)
	require.NoError(t, err)

	issuerSigned, err := ExtractIssuerSignedFromDeviceResponse(deviceResponse)
	require.NoError(t, err)

	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	assert.Equal(t, "1.0", mso.Version)
	assert.Equal(t, SHA256, mso.DigestAlgorithm)
	assert.Equal(t, MDLDocType, mso.DocType)

	// Namespaces present in the MSO valueDigests map.
	assert.ElementsMatch(t,
		[]string{"org.iso.18013.5.1", "org.iso.18013.5.1.US"},
		keys(mso.ValueDigests),
	)

	// Digests for the mDL namespace — 13 entries, digestIDs 0..12.
	iso := mso.ValueDigests["org.iso.18013.5.1"]
	require.NotNil(t, iso)
	assert.ElementsMatch(t,
		[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		uint64Keys(iso),
	)
	expectedISO := map[uint64]string{
		0:  "75167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf",
		1:  "67e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed4571",
		2:  "3394372ddb78053f36d5d869780e61eda313d44a392092ad8e0527a2fbfe55ae",
		3:  "2e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac9ce86b8613db555",
		4:  "ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d59",
		5:  "fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d",
		6:  "7d83e507ae77db815de4d803b88555d0511d894c897439f5774056416a1c7533",
		7:  "f0549a145f1cf75cbeeffa881d4857dd438d627cf32174b1731c4c38e12ca936",
		8:  "b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e068f66",
		9:  "0b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c",
		10: "c98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c881",
		11: "b57dd036782f7b14c6a30faaaae6ccd5054ce88bdfa51a016ba75eda1edea948",
		12: "651f8736b18480fe252a03224ea087b5d10ca5485146c67c74ac4ec3112d4c3a",
	}
	for id, expected := range expectedISO {
		assert.Equal(t, expected, hex.EncodeToString(iso[id]), "digestID %d", id)
	}

	// Digests for the aamva-style US namespace — 4 entries.
	isoUS := mso.ValueDigests["org.iso.18013.5.1.US"]
	require.NotNil(t, isoUS)
	assert.ElementsMatch(t, []uint64{0, 1, 2, 3}, uint64Keys(isoUS))
	expectedUS := map[uint64]string{
		0: "d80b83d25173c484c5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c",
		1: "4d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ecf94bf35bbd2917e34",
		2: "8b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544",
		3: "c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a87",
	}
	for id, expected := range expectedUS {
		assert.Equal(t, expected, hex.EncodeToString(isoUS[id]), "US digestID %d", id)
	}

	// Device key (P-256) from Annex D.
	require.NotNil(t, mso.DeviceKey)
	expectedX, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_STATIC_DEVICE_KEY_X)
	expectedY, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_STATIC_DEVICE_KEY_Y)
	assert.Equal(t, expectedX, mso.DeviceKey.X)
	assert.Equal(t, expectedY, mso.DeviceKey.Y)

	// deviceKeyInfo.keyAuthorizations is absent in this vector.
	assert.Empty(t, mso.DeviceKeyAuthorizedNamespaces)
	assert.Empty(t, mso.DeviceKeyAuthorizedDataElements)

	// Validity info — signed/validFrom/validUntil are the timestamps in Annex D.
	assert.Equal(t, time.UnixMilli(1601559002000).UTC(), mso.ValidityInfo.Signed.UTC())
	assert.Equal(t, time.UnixMilli(1601559002000).UTC(), mso.ValidityInfo.ValidFrom.UTC())
	assert.Equal(t, time.UnixMilli(1633095002000).UTC(), mso.ValidityInfo.ValidUntil.UTC())
	assert.Nil(t, mso.ValidityInfo.ExpectedUpdate)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uint64Keys[V any](m map[uint64]V) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
