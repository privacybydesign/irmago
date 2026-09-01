package eudi

import (
	"encoding/pem"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// List-delivered anchors: what a recognized anchor list installs into the trust
// models, and the two things it must never do — reach the trust-list pool, or
// take anything away from the compiled-in floor.

func caPem(t *testing.T, name string) (pemBytes []byte, leafLevel func(*TrustModel) clientmodels.TrustLevel) {
	t.Helper()
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName(name+" Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName(name), rootCert, rootKey, testdata.PkiOption_None, nil)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		func(tm *TrustModel) clientmodels.TrustLevel { return tm.Classify(leaf) }
}

func TestSetListTrustAnchors_InstallsIntoTheIssuerAndVerifierPoolsOnly(t *testing.T) {
	conf := newTestConfiguration(t)
	require.NoError(t, conf.Reload())
	trustListAnchorsBefore := len(conf.TrustLists.Anchors())

	issuerCa, issuerLeaf := caPem(t, "Listed Issuer CA")
	verifierCa, verifierLeaf := caPem(t, "Listed Verifier CA")

	require.NoError(t, conf.SetListTrustAnchors(
		[]ExtraTrustAnchor{{PEM: issuerCa, Confers: clientmodels.TrustLevel_Medium, CRLDistributionPoints: []string{"https://ca.example/issuer.crl"}}},
		[]ExtraTrustAnchor{{PEM: verifierCa, Confers: clientmodels.TrustLevel_High}},
	))

	require.Equal(t, clientmodels.TrustLevel_Medium, issuerLeaf(&conf.Issuers))
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, issuerLeaf(&conf.Verifiers), "an issuer CA anchors issuers only")
	require.Equal(t, clientmodels.TrustLevel_High, verifierLeaf(&conf.Verifiers))
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, verifierLeaf(&conf.Issuers))
	require.Contains(t, conf.Issuers.state().distributionPoints, "https://ca.example/issuer.crl",
		"the CRLs the listed CA issues join the sync")

	require.Len(t, conf.TrustLists.Anchors(), trustListAnchorsBefore,
		"no list can widen the set of keys allowed to sign lists")

	// A reload for any other reason keeps them.
	require.NoError(t, conf.Reload())
	require.Equal(t, clientmodels.TrustLevel_Medium, issuerLeaf(&conf.Issuers))

	// And replacing the set with nothing takes them out again.
	require.NoError(t, conf.SetListTrustAnchors(nil, nil))
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, issuerLeaf(&conf.Issuers), "a withdrawn CA is gone on the next reload")
}

func TestSetListTrustAnchors_APinnedAnchorKeepsTheStrongerLevel(t *testing.T) {
	conf := newTestConfiguration(t)
	// The compiled-in issuer CA, at high.
	require.NoError(t, conf.Reload())
	pinned := conf.Issuers.Anchors()
	require.Len(t, pinned, 1)

	// A list naming the same certificate at medium: promotion is the list's to
	// give, demotion is not.
	pinnedPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pinned[0].Certificate.Raw})
	require.NoError(t, conf.SetListTrustAnchors(
		[]ExtraTrustAnchor{{PEM: pinnedPem, Confers: clientmodels.TrustLevel_Medium}}, nil))

	anchors := conf.Issuers.Anchors()
	require.Len(t, anchors, 1, "the same certificate is one anchor")
	require.Equal(t, clientmodels.TrustLevel_High, anchors[0].Level, "level = max(pinned, list)")
}

func TestSetListTrustAnchors_AnAnchorThatDoesNotInstallIsSkippedNotFatal(t *testing.T) {
	conf := newTestConfiguration(t)
	require.NoError(t, conf.Reload())
	good, goodLeaf := caPem(t, "Good Listed CA")

	// A leaf where a CA should be: the wallet's strict mode refuses it as an
	// anchor. The list is fail-soft, so the rest still installs and the reload
	// still publishes.
	conf.SetCertificateVerificationMode(StrictCertificateVerification)
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Leafy Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Leafy CA"), rootCert, rootKey, testdata.PkiOption_None, nil)
	leafAsAnchor := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mintLeaf(t, caCert, caKey, testdata.PkiOption_None).Raw})

	require.NoError(t, conf.SetListTrustAnchors(
		[]ExtraTrustAnchor{
			{PEM: leafAsAnchor, Confers: clientmodels.TrustLevel_High},
			{PEM: good, Confers: clientmodels.TrustLevel_Medium},
		}, nil))
	require.Equal(t, clientmodels.TrustLevel_Medium, goodLeaf(&conf.Issuers))
}
