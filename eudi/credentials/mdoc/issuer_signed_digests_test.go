package mdoc

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuerSignedDigestsMatchMSO is inspired by multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/response/DeviceResponseParserTest.kt
//	  -> testDeviceResponseParserWithVectors()  (the digest-match assertions)
//
// Proves the core selective-disclosure invariant from ISO 18013-5 §9.1.2.5:
// for every IssuerSignedItem the wallet holds, SHA-256 over its tag-24-wrapped
// CBOR encoding MUST equal the digest that the issuer committed to in the MSO.
// This is the mechanism the verifier uses to prove no tampering between
// issuance and presentation.
func TestIssuerSignedDigestsMatchMSO(t *testing.T) {
	deviceResponse, err := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE)
	require.NoError(t, err)

	issuerSigned, err := ExtractIssuerSignedFromDeviceResponse(deviceResponse)
	require.NoError(t, err)

	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	for ns, items := range issuerSigned.Namespaces {
		nsDigests, ok := mso.ValueDigests[ns]
		require.True(t, ok, "MSO has no valueDigests for namespace %q", ns)

		for _, item := range items {
			computed, err := item.Digest(mso.DigestAlgorithm)
			require.NoError(t, err, "digest(%s/%s)", ns, item.ElementIdentifier)

			expected, ok := nsDigests[item.DigestID]
			require.True(t, ok, "MSO missing digestID %d for %s/%s",
				item.DigestID, ns, item.ElementIdentifier)

			assert.Equal(t,
				hex.EncodeToString(expected),
				hex.EncodeToString(computed),
				"digest mismatch for %s/%s (digestID %d)",
				ns, item.ElementIdentifier, item.DigestID,
			)
		}
	}
}

// TestIssuerSignedDigestsMismatchWhenTampered is transpiled from multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/response/DeviceResponseParserTest.kt
//	  -> testDeviceResponseParserWithVectorsMalformedIssuerItem()
//
// Flips one byte of the "Doe" family_name value (offset 200 in the encoded
// DeviceResponse) to make it "Foe", and asserts the digest check for that item
// now fails while all others still verify.
func TestIssuerSignedDigestsMismatchWhenTampered(t *testing.T) {
	deviceResponse, err := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE)
	require.NoError(t, err)

	// Sanity-check the offset matches the Kotlin test's assumption.
	require.Equal(t, byte(0x44), deviceResponse[200], "unexpected byte at offset 200")
	deviceResponse[200] = 0x46 // 'D' -> 'F'

	issuerSigned, err := ExtractIssuerSignedFromDeviceResponse(deviceResponse)
	require.NoError(t, err)

	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	items := issuerSigned.Namespaces[MDLNamespace]
	require.NotEmpty(t, items)

	mismatches := 0
	for _, item := range items {
		computed, err := item.Digest(mso.DigestAlgorithm)
		require.NoError(t, err)
		expected := mso.ValueDigests[MDLNamespace][item.DigestID]
		if hex.EncodeToString(expected) != hex.EncodeToString(computed) {
			mismatches++
			assert.Equal(t, "family_name", item.ElementIdentifier,
				"only family_name should fail digest check")
			assert.Equal(t, "Foe", mustDecodeTstr(t, item.ElementValue))
		}
	}
	assert.Equal(t, 1, mismatches, "expected exactly one digest mismatch")
}
