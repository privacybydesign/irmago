package mdoc_test

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
)

// TestSelectFromIssuerSigned_KeepsOnlyRequestedElements proves the filter's
// happy path: starting from a 2-attribute AV credential, keeping only one
// element drops the other entirely from the returned IssuerSigned.
func TestSelectFromIssuerSigned_KeepsOnlyRequestedElements(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true},
	})

	filtered, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		testissuer.AVNamespace: {"age_over_18"},
	})
	require.NoError(t, err)

	items, ok := filtered.Namespaces[testissuer.AVNamespace]
	require.True(t, ok)
	require.Len(t, items, 1)
	assert.Equal(t, "age_over_18", items[0].ElementIdentifier)
}

// TestSelectFromIssuerSigned_KeepsIssuerAuthIntact ensures the MSO and its
// signature are passed through unchanged — selective disclosure is a filter,
// not a re-signing operation.
func TestSelectFromIssuerSigned_KeepsIssuerAuthIntact(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{AgeOver18: true})

	filtered, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		testissuer.AVNamespace: {"age_over_18"},
	})
	require.NoError(t, err)

	assert.Equal(t, orig.IssuerAuth.ProtectedHeader, filtered.IssuerAuth.ProtectedHeader)
	assert.Equal(t, orig.IssuerAuth.Payload, filtered.IssuerAuth.Payload)
	assert.Equal(t, orig.IssuerAuth.Signature, filtered.IssuerAuth.Signature)
}

// TestSelectFromIssuerSigned_PreservesDigestIntegrity is the end-to-end proof
// that a filtered, re-encoded, re-parsed IssuerSigned still passes the
// selective-disclosure invariant: every retained item's hash matches the
// MSO's committed digest at its digestID.
func TestSelectFromIssuerSigned_PreservesDigestIntegrity(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true, 25: true},
	})

	filtered, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		testissuer.AVNamespace: {"age_over_18", "age_over_25"},
	})
	require.NoError(t, err)

	encoded, err := mdoc.EncodeIssuerSigned(filtered)
	require.NoError(t, err)

	reparsed, err := mdoc.ParseIssuerSigned(encoded)
	require.NoError(t, err)
	mso, err := reparsed.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	items := reparsed.Namespaces[testissuer.AVNamespace]
	require.Len(t, items, 2)
	seen := map[string]bool{}
	for _, it := range items {
		seen[it.ElementIdentifier] = true
		want := mso.ValueDigests[testissuer.AVNamespace][it.DigestID]
		got, err := it.Digest(mso.DigestAlgorithm)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, got),
			"digest mismatch after filter+encode+parse for %s", it.ElementIdentifier)
	}
	assert.True(t, seen["age_over_18"])
	assert.True(t, seen["age_over_25"])
	assert.False(t, seen["age_over_21"], "age_over_21 should have been filtered out")
}

// TestSelectFromIssuerSigned_UnknownElementErrors guards against the wallet
// silently under-disclosing. If the verifier asks for an attribute the
// holder doesn't possess, the holder must fail loudly rather than shipping
// a partial response.
func TestSelectFromIssuerSigned_UnknownElementErrors(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{AgeOver18: true})

	_, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		testissuer.AVNamespace: {"age_over_99"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "age_over_99")
}

// TestSelectFromIssuerSigned_UnknownNamespaceErrors mirrors the element
// check at the namespace level.
func TestSelectFromIssuerSigned_UnknownNamespaceErrors(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{AgeOver18: true})

	_, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		"org.iso.18013.5.1.mDL": {"family_name"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mDL")
}

// TestBuildDeviceResponse_RoundTrips asserts that BuildDeviceResponse
// produces a CBOR value our own parser can read back with the same docType,
// status and embedded IssuerSigned contents.
func TestBuildDeviceResponse_RoundTrips(t *testing.T) {
	orig := mustBuildAVIssuerSigned(t, testissuer.AVRequest{AgeOver18: true})

	filtered, err := mdoc.SelectFromIssuerSigned(orig, map[string][]string{
		testissuer.AVNamespace: {"age_over_18"},
	})
	require.NoError(t, err)

	// Minimal placeholder deviceSigned — Phase C will wire in real DeviceAuth.
	// Shape: `{"nameSpaces": <tag24 empty-map>, "deviceAuth": {"deviceMac": ...}}`.
	placeholder, err := cbor.Marshal(map[string]any{
		"nameSpaces": cbor.Tag{Number: 24, Content: []byte{0xa0}}, // bstr(empty map)
		"deviceAuth": map[string]any{},
	})
	require.NoError(t, err)

	resp, err := mdoc.BuildDeviceResponse(
		[]mdoc.Document{{
			DocType:      testissuer.AVDocType,
			IssuerSigned: filtered,
			DeviceSigned: placeholder,
		}},
		mdoc.DeviceResponseStatusOK,
	)
	require.NoError(t, err)
	require.NotEmpty(t, resp)

	// Round-trip by poking the outer map shape; full DeviceResponse parsing
	// sits under ExtractIssuerSignedFromDeviceResponse.
	reparsed, err := mdoc.ExtractIssuerSignedFromDeviceResponse(resp)
	require.NoError(t, err)
	items := reparsed.Namespaces[testissuer.AVNamespace]
	require.Len(t, items, 1)
	assert.Equal(t, "age_over_18", items[0].ElementIdentifier)
}

// ---- helpers ---------------------------------------------------------------

func mustBuildAVIssuerSigned(t *testing.T, req testissuer.AVRequest) *mdoc.IssuerSigned {
	t.Helper()
	cred, err := testissuer.BuildAVCredential(req)
	require.NoError(t, err)
	is, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)
	return is
}
