package wallet

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey() [32]byte {
	var k [32]byte
	copy(k[:], "0123456789abcdef0123456789abcdef")
	return k
}

func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	w, err := New(Config{
		DataDir: t.TempDir(),
		AesKey:  testKey(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestWalletLifecycle(t *testing.T) {
	w := newTestWallet(t)

	creds, err := w.Credentials()
	require.NoError(t, err)
	require.Empty(t, creds)

	logs, err := w.Logs(10)
	require.NoError(t, err)
	require.Empty(t, logs)

	require.NoError(t, w.Reset())
}

func TestReceiveRequiresRedirectURI(t *testing.T) {
	w := newTestWallet(t)
	_, err := w.Receive("openid-credential-offer://example", "", nil)
	require.Error(t, err)
}

// TestE2E runs a full issue-then-present cycle against real infrastructure. It
// is opt-in: set WALLET_POC_OFFER to an OpenID4VCI credential offer URI (and
// optionally WALLET_POC_PRESENT to an OpenID4VP request URI, WALLET_POC_TXCODE
// to a pre-authorized transaction code). Point these at the in-repo issuer /
// verifier harness or the EUDI reference services. Runs in developer mode so it
// accepts staging trust anchors and insecure endpoints.
func TestE2E(t *testing.T) {
	offer := os.Getenv("WALLET_POC_OFFER")
	if offer == "" {
		t.Skip("set WALLET_POC_OFFER to run the end-to-end issuance/presentation test")
	}

	txCode := os.Getenv("WALLET_POC_TXCODE")
	policy := FuncPolicy{
		TransactionCodeFunc: func() (string, bool) {
			if txCode == "" {
				return "", false
			}
			return txCode, true
		},
	}

	w, err := New(Config{
		DataDir:       t.TempDir(),
		AesKey:        testKey(),
		DeveloperMode: true,
		Policy:        policy,
	})
	require.NoError(t, err)
	defer w.Close()

	redirect := os.Getenv("WALLET_POC_REDIRECT")
	if redirect == "" {
		redirect = "openid4vci://callback"
	}

	issued, err := w.Receive(offer, redirect, nil)
	require.NoError(t, err)
	require.NotEmpty(t, issued, "expected at least one credential to be issued")

	stored, err := w.Credentials()
	require.NoError(t, err)
	require.NotEmpty(t, stored)

	present := os.Getenv("WALLET_POC_PRESENT")
	if present == "" {
		t.Log("WALLET_POC_PRESENT not set; skipping presentation leg")
		return
	}

	res, err := w.Present(present)
	require.NoError(t, err)
	require.NotNil(t, res)
	t.Logf("disclosed %d credential(s)", len(res.Disclosed))
}
