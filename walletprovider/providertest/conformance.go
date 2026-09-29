package providertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/walletprovider"
)

// Run checks the behaviour the wallet relies on from any
// walletprovider.WalletProvider. newProvider must return a provider backed by
// a fresh wallet unit, with a possession key of its own, each time it is
// called; the suite gives it a fresh in-memory Host. pin must be a PIN the
// provider accepts, wrongPin one that differs from it.
//
// Both the fake in this module and every real provider run this suite, which
// is how the contract is enforced without either repository's tests touching
// the other.
func Run(t *testing.T, newProvider walletprovider.Factory, pin, wrongPin string) {
	ctx := context.Background()
	fresh := func(t *testing.T) walletprovider.WalletProvider {
		t.Helper()
		p, err := newProvider(NewHost())
		require.NoError(t, err, "new provider")
		return p
	}
	activated := func(t *testing.T) walletprovider.WalletProvider {
		t.Helper()
		p := fresh(t)
		require.NoError(t, p.Activate(ctx, pin), "activate")
		return p
	}
	unlock := func(t *testing.T, p walletprovider.WalletProvider, purpose walletprovider.Purpose, withPin ...string) walletprovider.UnlockedWalletUnit {
		t.Helper()
		usePin := pin
		if len(withPin) > 0 {
			usePin = withPin[0]
		}
		u, err := p.Unlock(ctx, usePin, walletprovider.Scope{Purpose: purpose, Counterparty: "https://issuer.example"})
		require.NoError(t, err, "unlock")
		t.Cleanup(u.Close)
		return u
	}

	t.Run("a new wallet unit is not activated and cannot be unlocked", func(t *testing.T) {
		p := fresh(t)
		state, err := p.State(ctx)
		require.NoError(t, err)
		require.Equal(t, walletprovider.StateNotActivated, state)
		_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		require.ErrorIs(t, err, walletprovider.ErrNotActivated, "unlock before activation")
	})

	t.Run("activation makes the wallet unit active", func(t *testing.T) {
		p := activated(t)
		state, err := p.State(ctx)
		require.NoError(t, err)
		require.Equal(t, walletprovider.StateActive, state)
	})

	t.Run("an instance attestation needs an active wallet unit", func(t *testing.T) {
		p := fresh(t)
		_, err := p.InstanceAttestation(ctx, &newKey(t).PublicKey)
		require.ErrorIs(t, err, walletprovider.ErrNotActivated, "before activation")
	})

	t.Run("an instance attestation binds the given key and has a status of its own", func(t *testing.T) {
		p := activated(t)
		var indices []int
		for range 2 {
			key := newKey(t)
			wia, err := p.InstanceAttestation(ctx, &key.PublicKey)
			require.NoError(t, err)
			a, err := ParseInstanceAttestation(wia)
			require.NoError(t, err, "instance attestation")
			require.True(t, a.Key.Equal(&key.PublicKey), "cnf.jwk is the key it was asked to bind")
			indices = append(indices, a.StatusIndex)
		}
		// Never the same index twice: one index per wallet unit would link
		// every issuance of the wallet. A collision of two random indices is
		// possible but rare enough for a test.
		require.NotEqual(t, indices[0], indices[1], "two instance attestations share a status index")

		log, err := unlock(t, p, walletprovider.PurposeTransactionLog).Transactions(ctx, time.Time{}, 50)
		require.NoError(t, err)
		attested := 0
		for _, tx := range log {
			if tx.Operation == walletprovider.OperationAttestInstance && tx.Succeeded {
				attested++
			}
		}
		require.Equal(t, 2, attested, "both instance attestations are in the transaction log: %+v", log)
	})

	t.Run("a wrong PIN is reported by Unlock with the attempts remaining", func(t *testing.T) {
		p := activated(t)
		_, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		incorrect, ok := errors.AsType[*walletprovider.PinIncorrectError](err)
		require.True(t, ok, "got %v, want *PinIncorrectError", err)
		require.GreaterOrEqual(t, incorrect.Remaining, 1, "attempts remaining after one wrong PIN")
		// The right PIN still works afterwards.
		unlock(t, p, walletprovider.PurposeDisclosureKB)
	})

	t.Run("repeated wrong PINs block the wallet unit", func(t *testing.T) {
		p := activated(t)
		for range 100 {
			_, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
			if blocked, ok := errors.AsType[*walletprovider.PinBlockedError](err); ok {
				require.GreaterOrEqual(t, blocked.Duration, time.Duration(0))
				_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
				_, stillBlocked := errors.AsType[*walletprovider.PinBlockedError](err)
				require.True(t, stillBlocked, "right PIN while blocked: got %v, want *PinBlockedError", err)
				return
			}
			_, incorrect := errors.AsType[*walletprovider.PinIncorrectError](err)
			require.True(t, incorrect, "got %v, want *PinIncorrectError or *PinBlockedError", err)
		}
		require.Fail(t, "never blocked after 100 wrong PINs")
	})

	t.Run("generated keys sign ES256 over the exact signing input", func(t *testing.T) {
		p := activated(t)
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		keys, _, err := u.GenerateKeys(ctx, 3, nil)
		require.NoError(t, err)
		require.Len(t, keys, 3)
		reqs := make([]walletprovider.SignRequest, len(keys))
		refs := map[string]bool{}
		for i, k := range keys {
			require.NotEmpty(t, k.Ref, "key %d has no ref", i)
			require.NotNil(t, k.Public, "key %d has no public key", i)
			require.False(t, refs[k.Ref], "duplicate ref %q", k.Ref)
			refs[k.Ref] = true
			reqs[i] = walletprovider.SignRequest{Ref: k.Ref, SigningInput: []byte("header.payload-" + k.Ref)}
		}
		sigs, err := u.Sign(ctx, reqs)
		require.NoError(t, err)
		require.Len(t, sigs, len(reqs))
		for i, sig := range sigs {
			require.True(t, verifyES256(keys[i].Public, reqs[i].SigningInput, sig), "signature %d verifies under its key", i)
		}
	})

	t.Run("key generation without a request gives no key attestation", func(t *testing.T) {
		p := activated(t)
		_, ka, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 2, nil)
		require.NoError(t, err)
		require.Nil(t, ka)
	})

	t.Run("a key attestation covers exactly the generated keys, with the nonce and the protection the provider reports", func(t *testing.T) {
		p := activated(t)
		protection, err := p.KeyProtection(ctx)
		require.NoError(t, err)
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)

		var indices []int
		for _, nonce := range []string{"c-nonce-1", ""} {
			keys, raw, err := u.GenerateKeys(ctx, 3, &walletprovider.KeyAttestationRequest{Nonce: nonce})
			require.NoError(t, err)
			ka, err := ParseKeyAttestation(raw)
			require.NoError(t, err, "key attestation")
			require.Len(t, ka.AttestedKeys, len(keys))
			for i, k := range keys {
				require.True(t, ka.AttestedKeys[i].Equal(k.Public), "attested key %d is generated key %d", i, i)
			}
			require.Equal(t, nonce, ka.Nonce)
			require.ElementsMatch(t, protection.KeyStorage, ka.KeyStorage)
			require.ElementsMatch(t, protection.UserAuthentication, ka.UserAuthentication)
			indices = append(indices, ka.StatusIndex)
		}
		// As for instance attestations: never one index for two attestations.
		require.NotEqual(t, indices[0], indices[1], "two key attestations share a status index")
	})

	t.Run("keys survive into a later unlock for disclosure", func(t *testing.T) {
		p := activated(t)
		keys, _, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1, nil)
		require.NoError(t, err)
		input := []byte("kb-jwt signing input")
		sigs, err := unlock(t, p, walletprovider.PurposeDisclosureKB).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: input}})
		require.NoError(t, err)
		require.True(t, verifyES256(keys[0].Public, input, sigs[0]), "disclosure signature verifies")
	})

	t.Run("a closed unlock is expired", func(t *testing.T) {
		p := activated(t)
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		u.Close()
		u.Close()
		_, _, err := u.GenerateKeys(ctx, 1, nil)
		require.ErrorIs(t, err, walletprovider.ErrUnlockExpired)
	})

	t.Run("removed keys can no longer sign", func(t *testing.T) {
		p := activated(t)
		keys, _, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1, nil)
		require.NoError(t, err)
		require.NoError(t, p.RemoveKeys(ctx, []string{keys[0].Ref, "unknown-ref"}))
		_, err = unlock(t, p, walletprovider.PurposeDisclosureKB).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: []byte("x")}})
		require.Error(t, err, "signing with a removed key")
	})

	t.Run("a PIN change is in the transaction log", func(t *testing.T) {
		p := activated(t)
		u, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
		require.NoError(t, err)
		require.NoError(t, u.ChangePin(ctx, wrongPin))
		log, err := unlock(t, p, walletprovider.PurposeTransactionLog, wrongPin).Transactions(ctx, time.Time{}, 50)
		require.NoError(t, err)
		for _, tx := range log {
			if tx.Operation == walletprovider.OperationChangePin && tx.Succeeded {
				return
			}
		}
		require.Failf(t, "no PIN change in the log", "%+v", log)
	})

	t.Run("a changed PIN replaces the old one and keeps the keys", func(t *testing.T) {
		p := activated(t)
		keys, _, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1, nil)
		require.NoError(t, err)
		u, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
		require.NoError(t, err)
		require.NoError(t, u.ChangePin(ctx, wrongPin), "change PIN")
		_, _, err = u.GenerateKeys(ctx, 1, nil)
		require.ErrorIs(t, err, walletprovider.ErrUnlockExpired, "unlock after a PIN change")
		_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		require.Error(t, err, "the old PIN still unlocks")
		input := []byte("after the change")
		sigs, err := unlock(t, p, walletprovider.PurposeDisclosureKB, wrongPin).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: input}})
		require.NoError(t, err, "sign with the new PIN")
		require.True(t, verifyES256(keys[0].Public, input, sigs[0]), "a key from before the change signs under the new PIN")
	})

	t.Run("the transaction log records activation, a refused PIN, key generation and signing, newest first", func(t *testing.T) {
		p := activated(t)
		_, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		require.Error(t, err, "a wrong PIN unlocked")
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		keys, _, err := u.GenerateKeys(ctx, 1, nil)
		require.NoError(t, err)
		_, err = u.Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: []byte("proof")}})
		require.NoError(t, err)

		log, err := unlock(t, p, walletprovider.PurposeTransactionLog).Transactions(ctx, time.Time{}, 50)
		require.NoError(t, err)
		var activation, rejected, generated, signed bool
		for i, tx := range log {
			if i > 0 {
				require.False(t, tx.Time.After(log[i-1].Time), "transaction %d is newer than the one before it", i)
			}
			require.NotEmpty(t, tx.ID, "transaction %d has no ID", i)
			switch tx.Operation {
			case walletprovider.OperationActivate:
				activation = activation || tx.Succeeded
			case walletprovider.OperationRejected:
				rejected = rejected || !tx.Succeeded
			case walletprovider.OperationGenerateKeys:
				generated = generated || tx.Succeeded
			case walletprovider.OperationSign:
				if tx.Purpose == walletprovider.PurposeIssuancePoP && tx.Counterparty == "https://issuer.example" && tx.Succeeded {
					signed = true
				}
			}
		}
		require.True(t, activation && rejected && generated && signed,
			"log records the activation (%v), the refused PIN (%v), the key generation (%v) and the issuance signature (%v): %+v",
			activation, rejected, generated, signed, log)

		short, err := unlock(t, p, walletprovider.PurposeTransactionLog).Transactions(ctx, time.Time{}, 1)
		require.NoError(t, err)
		require.Len(t, short, 1, "a page of one")
	})

	t.Run("a revoked wallet unit cannot be unlocked", func(t *testing.T) {
		p := activated(t)
		require.NoError(t, p.Revoke(ctx))
		state, err := p.State(ctx)
		require.NoError(t, err)
		require.Equal(t, walletprovider.StateRevoked, state)
		_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		require.ErrorIs(t, err, walletprovider.ErrNotActivated)
		_, err = p.InstanceAttestation(ctx, &newKey(t).PublicKey)
		require.ErrorIs(t, err, walletprovider.ErrNotActivated, "instance attestation after revocation")
	})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func verifyES256(pub *ecdsa.PublicKey, input, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
