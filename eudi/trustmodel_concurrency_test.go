package eudi

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// Classify runs on the session path while the CRL refresh job reloads the trust
// model from its own goroutine. A reload assembles the next state off to the side
// and publishes it whole, so a reader sees either the state before or the state
// after — never an emptied middle, and never the roots of one reload beside the
// revocation lists of another.
//
// Each subtest below fails on a model that is emptied and refilled in place: the
// first two see the anchor go missing, the third sees a revoked certificate
// admitted while the revocation lists are being rebuilt.

func TestTrustModel_ReadersNeverSeeAHalfBuiltReload(t *testing.T) {
	t.Run("the level lookup", testAnchorLevelConcurrentWithReload)
	t.Run("Classify itself", testClassifyConcurrentWithReload)
	t.Run("a revoked leaf stays refused", testRevokedLeafStaysRefusedDuringReload)
}

func testAnchorLevelConcurrentWithReload(t *testing.T) {
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	root := issuerRootOf(t, tm)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)
	require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(leaf), "the fixture classifies before the readers start")

	stop := reloadContinuously(t, tm, caCert, root, nil)
	defer stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 200_000 {
				level, ok := tm.anchorLevel(caCert)
				require.True(t, ok, "every published state anchors the CA, so it is never absent")
				require.Equal(t, clientmodels.TrustLevel_High, level)
			}
		})
	}
	readers.Wait()
}

func testClassifyConcurrentWithReload(t *testing.T) {
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	root := issuerRootOf(t, tm)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)

	stop := reloadContinuously(t, tm, caCert, root, nil)
	defer stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			// Far fewer iterations: every one of these builds a chain, which is
			// what makes the session path the slower way to reach the state.
			for range 200 {
				require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(leaf),
					"a session sees a complete state, so the anchor's level, every time")
			}
		})
	}
	readers.Wait()
}

func testRevokedLeafStaysRefusedDuringReload(t *testing.T) {
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	root := issuerRootOf(t, tm)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)

	crlTemplate := testdata.GetDefaultCrlTemplate(caCert)
	crlTemplate.RevokedCertificateEntries = []x509.RevocationListEntry{{
		SerialNumber:   leaf.SerialNumber,
		RevocationTime: time.Now().Add(-time.Minute),
	}}
	crlDer, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlDer)
	require.NoError(t, err)
	crls := []*x509.RevocationList{crl}

	tm.mutate(func(s *trustState) { s.revocationLists = crls })
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(leaf), "the fixture refuses before the readers start")

	stop := reloadContinuously(t, tm, caCert, root, crls)
	defer stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 200 {
				require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(leaf),
					"a reload in progress must never let a revoked certificate through")
			}
		})
	}
	readers.Wait()
}

// reloadContinuously does what a reload does — start an empty pending state,
// install the anchor chain and revocation lists into it, publish it — until the
// returned function is called, which also waits for the writer to finish.
func reloadContinuously(t *testing.T, tm *TrustModel, caCert, root *x509.Certificate, crls []*x509.RevocationList) (stop func()) {
	t.Helper()

	chainPem := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)

	stopped, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopped:
				return
			default:
				tm.clear()
				if err := tm.addTrustAnchors(clientmodels.TrustLevel_High, chainPem); err != nil {
					t.Errorf("reload: %v", err)
					return
				}
				tm.building().revocationLists = crls
				tm.commit()
			}
		}
	}()

	return func() {
		close(stopped)
		<-done
	}
}

// issuerRootOf returns the self-signed root the fixture gave as the CA's issuer.
// It is not an anchor — the CA is — but a reload needs it to rebuild the chain.
func issuerRootOf(t *testing.T, tm *TrustModel) *x509.Certificate {
	t.Helper()

	for _, cert := range tm.state().allCerts {
		if cert.Subject.ToRDNSequence().String() == cert.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	t.Fatal("the fixture installed no self-signed root")
	return nil
}
