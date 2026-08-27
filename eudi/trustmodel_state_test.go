package eudi

import (
	"crypto/x509"
	"testing"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// malformedAnchor is a PEM certificate block whose contents are not a certificate:
// the parser skips non-PEM bytes silently, so this is the shape that makes
// addTrustAnchors — and with it a Reload — fail.
var malformedAnchor = []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")

// mutate edits the state readers see, for tests that set a model up by hand
// rather than through a reload. Production code has no such path: it assembles a
// pending state and commits it.
func (tm *TrustModel) mutate(f func(s *trustState)) {
	f(tm.building())
	tm.commit()
}

// A reload that fails part-way publishes nothing. Before states were swapped
// whole, Reload emptied the model first and filled it back up step by step, so an
// error in between — an extra anchor that does not parse, say — left the wallet
// with no anchors and no revocation lists until the next CRL tick. With
// unanchored certificates admitted as low, that middle was fail-open: a revoked
// verifier passed the gate.
func TestReload_AFailedReloadKeepsTheLastCompleteState(t *testing.T) {
	conf := newTestConfiguration(t)
	require.NoError(t, conf.Reload())

	before := map[*TrustModel]*trustState{
		&conf.Issuers:    conf.Issuers.state(),
		&conf.Verifiers:  conf.Verifiers.state(),
		&conf.TrustLists: conf.TrustLists.state(),
	}
	require.False(t, before[&conf.Issuers].roots.Equal(x509.NewCertPool()), "the fixture loaded anchors")

	conf.ExtraIssuerTrustAnchors = []ExtraTrustAnchor{{PEM: malformedAnchor}}
	require.Error(t, conf.Reload())

	for tm, state := range before {
		require.Same(t, state, tm.state(), "a failed reload must not touch what readers see")
		require.Nil(t, tm.pending, "and leaves nothing half-built behind")
	}

	// The next successful reload publishes again.
	conf.ExtraIssuerTrustAnchors = nil
	require.NoError(t, conf.Reload())
	require.NotSame(t, before[&conf.Issuers], conf.Issuers.state())
}

// Before its first reload a model trusts nothing. A nil root pool would make
// x509.Verify fall back to the operating system's root store, which is the one
// thing an unloaded wallet must not do.
func TestTrustModel_VerifiesAgainstNoRootsBeforeTheFirstReload(t *testing.T) {
	conf := newTestConfiguration(t)

	opts := conf.Issuers.GetVerificationOptionsTemplate()
	require.NotNil(t, opts.Roots, "nil would mean the system root store")
	require.True(t, opts.Roots.Equal(x509.NewCertPool()))

	_, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Any Root"), testdata.PkiOption_None)
	require.Error(t, eudi_jwt.VerifyCertificate(&conf.Issuers, rootCert, nil))
	require.Empty(t, conf.Issuers.GetRevocationLists())
}

// The three models publish together: an error loading the third leaves the first
// two unpublished too, so the configuration never mixes a new issuer model with
// an old verifier one.
func TestReload_PublishesAllModelsOrNone(t *testing.T) {
	conf := newTestConfiguration(t)
	require.NoError(t, conf.Reload())
	issuersBefore := conf.Issuers.state()

	// Only the trust-list model is given something that cannot load.
	conf.ExtraTrustListTrustAnchors = []ExtraTrustAnchor{{PEM: malformedAnchor}}
	require.Error(t, conf.Reload())

	require.Same(t, issuersBefore, conf.Issuers.state(),
		"the issuer model had assembled fine, and still must not be published alone")
}
