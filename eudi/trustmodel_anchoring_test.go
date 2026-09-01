package eudi

import (
	"encoding/pem"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// An anchor is the CA that issues end-entity certificates, trusted for what it
// signs and for nothing its own issuer signed besides it. These tests pin the
// consequences: a sibling CA under the same root is a stranger, a CA anchors
// without its root, and the level is the anchor's, not the root's.

func TestAnchoring(t *testing.T) {
	t.Run("a sibling CA under the anchor's root is a stranger", testSiblingCaUnderSharedRootIsUnevaluated)
	t.Run("a CA anchors on its own, without its root", testCaAnchorsWithoutItsRoot)
	t.Run("two CAs under one root carry their own levels", testTwoCasUnderOneRootCarryTheirOwnLevels)
	t.Run("a chain whose issuer did not issue the anchor is skipped", testChainWithWrongIssuerIsSkipped)
	t.Run("in strict mode an end-entity certificate cannot anchor", testEndEntityCannotAnchorInStrictMode)
	t.Run("Anchors lists what was installed, with its level", testAnchorsListsInstalledAnchors)
}

func encodeChain(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// The reason anchors are CAs and not roots. All three Yivi anchors share one
// root; if the root were the anchor, a leaf under the issuer CA would validate
// in the verifier pool and the other way round.
func testSiblingCaUnderSharedRootIsUnevaluated(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Shared Root"), testdata.PkiOption_None)
	_, anchoredCa, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Anchored CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	siblingKey, siblingCa, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Sibling CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_High, encodeChain(anchoredCa.Raw, rootCert.Raw)))
	tm.commit()

	leaf := mintLeaf(t, siblingCa, siblingKey, testdata.PkiOption_None)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(leaf),
		"the root was given as the anchor's issuer, not as an anchor")
}

func testCaAnchorsWithoutItsRoot(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Absent Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Lone CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_Medium, encodeChain(caCert.Raw)))
	tm.commit()

	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)
	require.Equal(t, clientmodels.TrustLevel_Medium, tm.Classify(leaf),
		"a non-self-signed CA is a complete anchor; the list delivers CAs exactly this way")
}

func testTwoCasUnderOneRootCarryTheirOwnLevels(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Levels Root"), testdata.PkiOption_None)
	highKey, highCa, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("High CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	mediumKey, mediumCa, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Medium CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_High, encodeChain(highCa.Raw, rootCert.Raw)))
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_Medium, encodeChain(mediumCa.Raw, rootCert.Raw)))
	tm.commit()

	require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(mintLeaf(t, highCa, highKey, testdata.PkiOption_None)))
	require.Equal(t, clientmodels.TrustLevel_Medium, tm.Classify(mintLeaf(t, mediumCa, mediumKey, testdata.PkiOption_None)),
		"levels are the anchor's own, so a shared root cannot leak one CA's level to another")
}

func testChainWithWrongIssuerIsSkipped(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Real Root"), testdata.PkiOption_None)
	_, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Real CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	_, otherRoot := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Other Root"), testdata.PkiOption_None)

	tm, _ := setupTrustModelWithStoragePath(t)
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_High, encodeChain(caCert.Raw, otherRoot.Raw)))
	tm.commit()

	require.Empty(t, tm.Anchors(), "an issuer chain that does not issue the anchor is a malformed chain, not a courtesy")
}

func testEndEntityCannotAnchorInStrictMode(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("EE Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("EE CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)

	tm, _ := setupTrustModelWithStoragePath(t)
	tm.SetCertificateVerificationMode(StrictCertificateVerification)
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_High, encodeChain(leaf.Raw, caCert.Raw, rootCert.Raw)))
	tm.commit()

	require.Empty(t, tm.Anchors(), "a leaf vouches for nothing below it")
}

func testAnchorsListsInstalledAnchors(t *testing.T) {
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("List Root"), testdata.PkiOption_None)
	_, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Listed CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	require.Empty(t, tm.Anchors(), "nothing before the first commit")
	require.NoError(t, tm.addTrustAnchors(clientmodels.TrustLevel_Medium, encodeChain(caCert.Raw, rootCert.Raw)))
	require.Empty(t, tm.Anchors(), "and nothing until it commits")
	tm.commit()

	anchors := tm.Anchors()
	require.Len(t, anchors, 1)
	require.Equal(t, caCert.Raw, anchors[0].Certificate.Raw)
	require.Equal(t, clientmodels.TrustLevel_Medium, anchors[0].Level)
}
