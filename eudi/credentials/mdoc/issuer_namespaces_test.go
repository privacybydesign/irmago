package mdoc

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuerNamespacesParsing is transpiled from multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/issuersigned/IssuerNamespacesTest.kt
//	  -> testParsingAndEncoding()
//
// It parses the IssuerSigned.nameSpaces map from the ISO 18013-5 Annex D test
// vector and verifies every disclosed data element: digestId, random (salt),
// elementIdentifier, and the value for string/bytes elements. Tagged values
// (dates, driving_privileges) are covered indirectly via the digest-match test.
func TestIssuerNamespacesParsing(t *testing.T) {
	deviceResponse, err := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE)
	require.NoError(t, err)

	issuerSigned, err := ExtractIssuerSignedFromDeviceResponse(deviceResponse)
	require.NoError(t, err)

	require.Len(t, issuerSigned.Namespaces, 1)
	items, ok := issuerSigned.Namespaces[MDLNamespace]
	require.True(t, ok, "expected %q namespace", MDLNamespace)
	require.Len(t, items, 6)

	// Index by elementIdentifier so the test doesn't depend on disclosure order.
	byID := make(map[string]IssuerSignedItem, len(items))
	for _, it := range items {
		byID[it.ElementIdentifier] = it
	}

	// family_name
	familyName := byID["family_name"]
	assert.Equal(t, uint64(0), familyName.DigestID)
	assert.Equal(t,
		"8798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e9",
		hex.EncodeToString(familyName.Random),
	)
	assert.Equal(t, "Doe", mustDecodeTstr(t, familyName.ElementValue))

	// issue_date: tagged full-date (CBOR tag 1004, "2019-10-20"). Raw bytes only here.
	issueDate := byID["issue_date"]
	assert.Equal(t, uint64(3), issueDate.DigestID)
	assert.Equal(t,
		"b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d",
		hex.EncodeToString(issueDate.Random),
	)

	// expiry_date
	expiryDate := byID["expiry_date"]
	assert.Equal(t, uint64(4), expiryDate.DigestID)
	assert.Equal(t,
		"c7ffa307e5de921e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf",
		hex.EncodeToString(expiryDate.Random),
	)

	// document_number
	docNum := byID["document_number"]
	assert.Equal(t, uint64(7), docNum.DigestID)
	assert.Equal(t,
		"26052a42e5880557a806c1459af3fb7eb505d3781566329d0b604b845b5f9e68",
		hex.EncodeToString(docNum.Random),
	)
	assert.Equal(t, "123456789", mustDecodeTstr(t, docNum.ElementValue))

	// portrait — byte string equal to the standalone portrait test vector.
	portrait := byID["portrait"]
	assert.Equal(t, uint64(8), portrait.DigestID)
	assert.Equal(t,
		"d094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d",
		hex.EncodeToString(portrait.Random),
	)
	expectedPortrait, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE_PORTRAIT_DATA)
	assert.Equal(t, expectedPortrait, mustDecodeBstr(t, portrait.ElementValue))

	// driving_privileges
	drivingPriv := byID["driving_privileges"]
	assert.Equal(t, uint64(9), drivingPriv.DigestID)
	assert.Equal(t,
		"4599f81beaa2b20bd0ffcc9aa03a6f985befab3f6beaffa41e6354cdb2ab2ce4",
		hex.EncodeToString(drivingPriv.Random),
	)
}

// mustDecodeTstr decodes a CBOR-encoded text string. It is a small helper the
// package will expose (or equivalent) once the real decoder is wired up.
func mustDecodeTstr(t *testing.T, raw []byte) string {
	t.Helper()
	s, err := decodeTstr(raw)
	require.NoError(t, err)
	return s
}

func mustDecodeBstr(t *testing.T, raw []byte) []byte {
	t.Helper()
	b, err := decodeBstr(raw)
	require.NoError(t, err)
	return b
}
