package fake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

func TestFakeConforms(t *testing.T) {
	providertest.Run(t, fake.New(fake.Options{}), "12345", "54321")
}

func TestFakeUnlockExpiresWhenIdle(t *testing.T) {
	now := time.Now()
	p, err := fake.New(fake.Options{UnlockIdle: time.Minute, Now: func() time.Time { return now }})(providertest.NewHost())
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.Activate(ctx, "12345"))
	u, err := p.Unlock(ctx, "12345", walletprovider.Scope{Purpose: walletprovider.PurposeIssuancePoP})
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	_, _, err = u.GenerateKeys(ctx, 1, nil)
	require.ErrorIs(t, err, walletprovider.ErrUnlockExpired)
}

func TestFakeBlockLifts(t *testing.T) {
	now := time.Now()
	p, err := fake.New(fake.Options{MaxAttempts: 1, BlockDuration: time.Minute, Now: func() time.Time { return now }})(providertest.NewHost())
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.Activate(ctx, "12345"))
	_, err = p.Unlock(ctx, "00000", walletprovider.Scope{})
	require.True(t, isBlocked(err), "got %v, want *PinBlockedError", err)
	now = now.Add(2 * time.Minute)
	_, err = p.Unlock(ctx, "12345", walletprovider.Scope{})
	require.NoError(t, err, "unlock after the block lifted")
}

func isBlocked(err error) bool {
	_, ok := errors.AsType[*walletprovider.PinBlockedError](err)
	return ok
}

func TestFakeInstanceAttestationChainsToItsCA(t *testing.T) {
	ca, err := fake.NewAttestationCA()
	require.NoError(t, err)
	p, err := fake.New(fake.Options{AttestationCA: ca, ClientID: "test-client"})(providertest.NewHost())
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.Activate(ctx, "12345"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia, err := p.InstanceAttestation(ctx, &key.PublicKey)
	require.NoError(t, err)
	a, err := providertest.ParseInstanceAttestation(wia)
	require.NoError(t, err)
	require.Equal(t, "test-client", a.Subject)
	_, err = a.Chain[0].Verify(x509.VerifyOptions{Roots: ca.Roots()})
	require.NoError(t, err, "the WIA chains to the CA")
	require.Equal(t, 1, p.(*fake.Provider).InstanceAttestations())
}

func TestFakeRefusesInstanceAttestationWhileBlocked(t *testing.T) {
	p, err := fake.New(fake.Options{MaxAttempts: 1})(providertest.NewHost())
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.Activate(ctx, "12345"))
	_, err = p.Unlock(ctx, "00000", walletprovider.Scope{})
	require.True(t, isBlocked(err), "got %v, want *PinBlockedError", err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = p.InstanceAttestation(ctx, &key.PublicKey)
	require.ErrorIs(t, err, walletprovider.ErrAttestationRefused)
}

func TestLoadAttestationCA(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "eudi-pid-issuer-py", "wallet-attestation")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		return data
	}
	ca, err := fake.LoadAttestationCA(read("ca.pem"), read("signer.pem"), read("signer.key"))
	require.NoError(t, err)

	p, err := fake.New(fake.Options{AttestationCA: ca})(providertest.NewHost())
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.Activate(ctx, "12345"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wia, err := p.InstanceAttestation(ctx, &key.PublicKey)
	require.NoError(t, err)
	a, err := providertest.ParseInstanceAttestation(wia)
	require.NoError(t, err)
	_, err = a.Chain[0].Verify(x509.VerifyOptions{Roots: ca.Roots()})
	require.NoError(t, err)

	_, err = fake.LoadAttestationCA(read("ca.pem"), read("signer.pem"), read("ca.key"))
	require.Error(t, err, "a key that is not the signer's")
}
