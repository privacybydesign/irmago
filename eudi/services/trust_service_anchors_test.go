package services

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// recordingInstaller stands in for eudi.Configuration: it remembers what it was
// handed and how often.
type recordingInstaller struct {
	mu        sync.Mutex
	calls     int
	issuers   []eudi.ExtraTrustAnchor
	verifiers []eudi.ExtraTrustAnchor
}

func (r *recordingInstaller) SetListTrustAnchors(issuers, verifiers []eudi.ExtraTrustAnchor) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.issuers, r.verifiers = issuers, verifiers
	return nil
}

func anchorTestCa(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName(name+" Root"), testdata.PkiOption_None)
	_, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName(name), rootCert, rootKey, testdata.PkiOption_None, nil)
	return caCert
}

func TestTrustService_SyncListAnchors_InstallsWhatTheAnchorListDelivers(t *testing.T) {
	const listId = "urn:yivi:trustanchors:service-test"
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	issuerCa := anchorTestCa(t, "Service Test Issuer CA")
	server.Serve(t, signer, lote.NewTestAnchorList(listId, 1,
		lote.NewTestEntity("Operator", "",
			lote.NewTestCaService(trust.RoleIssuer, issuerCa, clientmodels.TrustLevel_Medium, "https://ca.example/issuer.crl"))))

	checker := lote.NewChecker(lote.Config{
		Sources:     []lote.Source{server.AnchorSource(listId, signer, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
	})
	service := NewTrustService(checker, nil, nil)
	installer := &recordingInstaller{}

	// Nothing fetched yet: nothing to install, and no call to say so.
	require.NoError(t, service.InstallListAnchorsInto(installer))
	require.Equal(t, 0, installer.calls)

	changed, err := service.RefreshLists(context.Background())
	require.NoError(t, err)
	require.True(t, changed, "a CA arriving changes the rung of everything under it")
	require.Equal(t, 1, installer.calls)
	require.Len(t, installer.issuers, 1)
	require.Empty(t, installer.verifiers)
	require.Equal(t, clientmodels.TrustLevel_Medium, installer.issuers[0].Confers)
	require.Equal(t, []string{"https://ca.example/issuer.crl"}, installer.issuers[0].CRLDistributionPoints)
	require.Contains(t, string(installer.issuers[0].PEM), "BEGIN CERTIFICATE")

	// The same list again: nothing to redo.
	changed, err = service.RefreshLists(context.Background())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, 1, installer.calls, "an unchanged anchor set reloads nothing")

	// Withdrawn: installed as an empty set, which is how the anchor leaves.
	withdrawn := lote.NewTestCaService(trust.RoleIssuer, issuerCa, clientmodels.TrustLevel_Medium, "https://ca.example/issuer.crl")
	withdrawn.Information.Status = lote.ServiceStatusWithdrawn
	server.Serve(t, signer, lote.NewTestAnchorList(listId, 2, lote.NewTestEntity("Operator", "", withdrawn)))

	changed, err = service.RefreshLists(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 2, installer.calls)
	require.Empty(t, installer.issuers)
}

func TestTrustService_WithoutAnInstallerTheAnchorListInstallsNothing(t *testing.T) {
	const listId = "urn:yivi:trustanchors:dark"
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestAnchorList(listId, 1,
		lote.NewTestEntity("Operator", "",
			lote.NewTestCaService(trust.RoleIssuer, anchorTestCa(t, "Dark CA"), clientmodels.TrustLevel_Medium))))

	checker := lote.NewChecker(lote.Config{
		Sources:     []lote.Source{server.AnchorSource(listId, signer, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
	})
	service := NewTrustService(checker, nil, nil)

	changed, err := service.RefreshLists(context.Background())
	require.NoError(t, err)
	require.False(t, changed, "read but installed nowhere is not a change the app can see")
}
