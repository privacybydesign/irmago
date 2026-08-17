package eudi

import (
	"crypto/x509"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// Classify runs on the session path while the CRL refresh job reloads the trust
// model from its own goroutine (Client.startCrlUpdateJob →
// Configuration.UpdateCertificateRevocationLists → Reload), so the anchor level
// map is read and rewritten at the same time. Unlike the pointers and slice
// headers the reload also replaces, an unsynchronised map is the one shape Go
// answers with "fatal error: concurrent map read and map write" — a throw no
// recover catches, so the wallet goes down rather than reading a stale level.
//
// Both subtests below fail on an unguarded map: the first reliably, since
// nothing slows its readers down, the second under -race.

func TestTrustModel_AnchorLevelsSurviveAConcurrentReload(t *testing.T) {
	t.Run("the level lookup", testAnchorLevelConcurrentWithReload)
	t.Run("Classify itself", testClassifyConcurrentWithReload)
}

func testAnchorLevelConcurrentWithReload(t *testing.T) {
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	root := selfSignedRootOf(t, tm)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)
	require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(leaf), "the fixture classifies before the readers start")

	stop := reloadAnchorLevels(t, tm, root)
	defer stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 200_000 {
				// Mid-reload the anchor is briefly absent, so both answers are
				// legitimate. What may not happen is a torn read of the map.
				if level, ok := tm.anchorLevel(root); ok {
					require.Equal(t, clientmodels.TrustLevel_High, level)
				}
			}
		})
	}
	readers.Wait()
}

func testClassifyConcurrentWithReload(t *testing.T) {
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	root := selfSignedRootOf(t, tm)
	leaf := mintLeaf(t, caCert, caKey, testdata.PkiOption_None)

	stop := reloadAnchorLevels(t, tm, root)
	defer stop()

	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			// Far fewer iterations: every one of these builds a chain, which is
			// what makes the session path the slower way to reach the map.
			for range 200 {
				require.Contains(t,
					[]clientmodels.TrustLevel{clientmodels.TrustLevel_High, clientmodels.TrustLevel_Unevaluated},
					tm.Classify(leaf),
					"a session sees either the anchor's level or no anchor, never a third thing")
			}
		})
	}
	readers.Wait()
}

// reloadAnchorLevels does to the level map what a reload does — empty it, then
// state the anchor's level again — until the returned function is called, which
// also waits for the writer to finish.
func reloadAnchorLevels(t *testing.T, tm *TrustModel, root *x509.Certificate) (stop func()) {
	t.Helper()

	stopped, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopped:
				return
			default:
				tm.clearAnchorLevels()
				tm.recordAnchorLevel(root, clientmodels.TrustLevel_High)
			}
		}
	}()

	return func() {
		close(stopped)
		<-done
	}
}

// selfSignedRootOf returns the anchor the fixture installed. The level map is
// keyed by the root, while classifyFixture hands back the CA under it.
func selfSignedRootOf(t *testing.T, tm *TrustModel) *x509.Certificate {
	t.Helper()

	for _, cert := range tm.allCerts {
		if cert.Subject.ToRDNSequence().String() == cert.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	t.Fatal("the fixture installed no self-signed root")
	return nil
}
