package client

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

const testAnchorListId = "urn:yivi:trustanchors:client-test"

// Through the real wiring: a CA published on an anchor list ends up in the
// wallet's issuer pool, leaves under it rank at the conferred level, and the
// trust-list pool is untouched.

func TestClient_RefreshTrustLists_InstallsAListedCa(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Listed Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Listed Issuer CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	_, leaf, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("issuer.example.com"), "issuer.example.com", caCert, caKey, "", testdata.PkiOption_None)

	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestAnchorList(testAnchorListId, 1,
		lote.NewTestEntity("Example CA Operator", "",
			lote.NewTestCaService(trust.RoleIssuer, caCert, clientmodels.TrustLevel_Medium, "https://ca.example/issuer.crl"))))

	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	c := newClientWithTrustLists(t, storagePath, signer,
		[]lote.Source{server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)})
	conf := c.openid4vpClient.Configuration
	trustListAnchors := len(conf.TrustLists.Anchors())

	require.Equal(t, clientmodels.TrustLevel_Unevaluated, conf.Issuers.Classify(leaf), "nothing before the first fetch")

	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, conf.Issuers.Classify(leaf), "the listed CA anchors its leaves at the conferred level")
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, conf.Verifiers.Classify(leaf), "in the issuer pool only")
	require.Len(t, conf.TrustLists.Anchors(), trustListAnchors, "and never in the trust-list pool")
	require.Contains(t, anchorSubjects(conf.Issuers.Anchors()), "Listed Issuer CA")

	// A restarted wallet has it from the persisted list, before any fetch.
	require.NoError(t, c.Close())
	restarted := newClientWithTrustLists(t, storagePath, signer,
		[]lote.Source{server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)})
	require.Equal(t, clientmodels.TrustLevel_Medium, restarted.openid4vpClient.Configuration.Issuers.Classify(leaf))
}

func TestClient_New_RefusesAMisconfiguredSource(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	unpinned := server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)
	unpinned.SignerSKI = nil

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")
	_, err := New(Config{
		StoragePath:           storagePath,
		IrmaConfigurationPath: filepath.Join(test.FindTestdataFolder(t), "irma_configuration"),
		EudiAppDataPath:       filepath.Join(storagePath, "eudi"),
		Handler:               &testhelpers.TestClientHandler{T: t},
		Signer:                test.NewSigner(t),
		AesKey:                aesKey,
		Locale:                "en",
		RecognizedTrustLists:  []lote.Source{unpinned},
	})
	require.ErrorContains(t, err, "SignerSKI", "an anchor source without a signer pin is a build error of the app")
}

func anchorSubjects(anchors []eudi.Anchor) []string {
	subjects := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		subjects = append(subjects, anchor.Certificate.Subject.CommonName)
	}
	return subjects
}
