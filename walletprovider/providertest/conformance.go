package providertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

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
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		return p
	}
	activated := func(t *testing.T) walletprovider.WalletProvider {
		t.Helper()
		p := fresh(t)
		if err := p.Activate(ctx, pin); err != nil {
			t.Fatalf("activate: %v", err)
		}
		return p
	}
	unlock := func(t *testing.T, p walletprovider.WalletProvider, purpose walletprovider.Purpose, withPin ...string) walletprovider.UnlockedWalletUnit {
		t.Helper()
		usePin := pin
		if len(withPin) > 0 {
			usePin = withPin[0]
		}
		u, err := p.Unlock(ctx, usePin, walletprovider.Scope{Purpose: purpose, Counterparty: "https://issuer.example"})
		if err != nil {
			t.Fatalf("unlock: %v", err)
		}
		t.Cleanup(u.Close)
		return u
	}

	t.Run("a new wallet unit is not activated and cannot be unlocked", func(t *testing.T) {
		p := fresh(t)
		state, err := p.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state != walletprovider.StateNotActivated {
			t.Fatalf("state = %q, want %q", state, walletprovider.StateNotActivated)
		}
		_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		if !errors.Is(err, walletprovider.ErrNotActivated) {
			t.Fatalf("unlock before activation: got %v, want ErrNotActivated", err)
		}
	})

	t.Run("activation makes the wallet unit active", func(t *testing.T) {
		p := activated(t)
		state, err := p.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state != walletprovider.StateActive {
			t.Fatalf("state = %q, want %q", state, walletprovider.StateActive)
		}
	})

	t.Run("a wrong PIN is reported by Unlock with the attempts remaining", func(t *testing.T) {
		p := activated(t)
		_, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		incorrect, ok := errors.AsType[*walletprovider.PinIncorrectError](err)
		if !ok {
			t.Fatalf("got %v, want *PinIncorrectError", err)
		}
		if incorrect.Remaining < 1 {
			t.Fatalf("remaining = %d after one wrong PIN", incorrect.Remaining)
		}
		// The right PIN still works afterwards.
		unlock(t, p, walletprovider.PurposeDisclosureKB)
	})

	t.Run("repeated wrong PINs block the wallet unit", func(t *testing.T) {
		p := activated(t)
		for range 100 {
			_, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
			if blocked, ok := errors.AsType[*walletprovider.PinBlockedError](err); ok {
				if blocked.Duration < 0 {
					t.Fatalf("blocked for %s", blocked.Duration)
				}
				_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
				if _, ok := errors.AsType[*walletprovider.PinBlockedError](err); !ok {
					t.Fatalf("right PIN while blocked: got %v, want *PinBlockedError", err)
				}
				return
			}
			if _, ok := errors.AsType[*walletprovider.PinIncorrectError](err); !ok {
				t.Fatalf("got %v, want *PinIncorrectError or *PinBlockedError", err)
			}
		}
		t.Fatal("never blocked after 100 wrong PINs")
	})

	t.Run("generated keys sign ES256 over the exact signing input", func(t *testing.T) {
		p := activated(t)
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		keys, err := u.GenerateKeys(ctx, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 3 {
			t.Fatalf("got %d keys, want 3", len(keys))
		}
		reqs := make([]walletprovider.SignRequest, len(keys))
		refs := map[string]bool{}
		for i, k := range keys {
			if k.Ref == "" || k.Public == nil {
				t.Fatalf("key %d has no ref or public key", i)
			}
			if refs[k.Ref] {
				t.Fatalf("duplicate ref %q", k.Ref)
			}
			refs[k.Ref] = true
			reqs[i] = walletprovider.SignRequest{Ref: k.Ref, SigningInput: []byte("header.payload-" + k.Ref)}
		}
		sigs, err := u.Sign(ctx, reqs)
		if err != nil {
			t.Fatal(err)
		}
		if len(sigs) != len(reqs) {
			t.Fatalf("got %d signatures, want %d", len(sigs), len(reqs))
		}
		for i, sig := range sigs {
			if !verifyES256(keys[i].Public, reqs[i].SigningInput, sig) {
				t.Fatalf("signature %d does not verify under its key", i)
			}
		}
	})

	t.Run("keys survive into a later unlock for disclosure", func(t *testing.T) {
		p := activated(t)
		keys, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		input := []byte("kb-jwt signing input")
		sigs, err := unlock(t, p, walletprovider.PurposeDisclosureKB).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: input}})
		if err != nil {
			t.Fatal(err)
		}
		if !verifyES256(keys[0].Public, input, sigs[0]) {
			t.Fatal("disclosure signature does not verify")
		}
	})

	t.Run("a closed unlock is expired", func(t *testing.T) {
		p := activated(t)
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		u.Close()
		u.Close()
		if _, err := u.GenerateKeys(ctx, 1); !errors.Is(err, walletprovider.ErrUnlockExpired) {
			t.Fatalf("got %v, want ErrUnlockExpired", err)
		}
	})

	t.Run("removed keys can no longer sign", func(t *testing.T) {
		p := activated(t)
		keys, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.RemoveKeys(ctx, []string{keys[0].Ref, "unknown-ref"}); err != nil {
			t.Fatal(err)
		}
		_, err = unlock(t, p, walletprovider.PurposeDisclosureKB).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: []byte("x")}})
		if err == nil {
			t.Fatal("signing with a removed key succeeded")
		}
	})

	t.Run("a PIN change is in the transaction log", func(t *testing.T) {
		p := activated(t)
		u, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
		if err != nil {
			t.Fatal(err)
		}
		if err := u.ChangePin(ctx, wrongPin); err != nil {
			t.Fatal(err)
		}
		log, err := unlock(t, p, walletprovider.PurposeTransactionLog, wrongPin).Transactions(ctx, time.Time{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, tx := range log {
			if tx.Operation == walletprovider.OperationChangePin && tx.Succeeded {
				return
			}
		}
		t.Fatalf("no PIN change in %+v", log)
	})

	t.Run("a changed PIN replaces the old one and keeps the keys", func(t *testing.T) {
		p := activated(t)
		keys, err := unlock(t, p, walletprovider.PurposeIssuancePoP).GenerateKeys(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		u, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
		if err != nil {
			t.Fatal(err)
		}
		if err := u.ChangePin(ctx, wrongPin); err != nil {
			t.Fatalf("change PIN: %v", err)
		}
		if _, err := u.GenerateKeys(ctx, 1); !errors.Is(err, walletprovider.ErrUnlockExpired) {
			t.Fatalf("unlock after a PIN change: got %v, want ErrUnlockExpired", err)
		}
		if _, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB}); err == nil {
			t.Fatal("the old PIN still unlocks")
		}
		input := []byte("after the change")
		sigs, err := unlock(t, p, walletprovider.PurposeDisclosureKB, wrongPin).Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: input}})
		if err != nil {
			t.Fatalf("sign with the new PIN: %v", err)
		}
		if !verifyES256(keys[0].Public, input, sigs[0]) {
			t.Fatal("a key from before the change does not sign under the new PIN")
		}
	})

	t.Run("the transaction log records activation, a refused PIN, key generation and signing, newest first", func(t *testing.T) {
		p := activated(t)
		if _, err := p.Unlock(ctx, wrongPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB}); err == nil {
			t.Fatal("a wrong PIN unlocked")
		}
		u := unlock(t, p, walletprovider.PurposeIssuancePoP)
		keys, err := u.GenerateKeys(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.Sign(ctx, []walletprovider.SignRequest{{Ref: keys[0].Ref, SigningInput: []byte("proof")}}); err != nil {
			t.Fatal(err)
		}

		log, err := unlock(t, p, walletprovider.PurposeTransactionLog).Transactions(ctx, time.Time{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		var activation, rejected, generated, signed bool
		for i, tx := range log {
			if i > 0 && tx.Time.After(log[i-1].Time) {
				t.Fatalf("transaction %d is newer than the one before it", i)
			}
			if tx.ID == "" {
				t.Fatalf("transaction %d has no ID", i)
			}
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
		if !activation || !rejected || !generated || !signed {
			t.Fatalf("log does not record the activation (%v), the refused PIN (%v), the key generation (%v) and the issuance signature (%v): %+v",
				activation, rejected, generated, signed, log)
		}

		if short, err := unlock(t, p, walletprovider.PurposeTransactionLog).Transactions(ctx, time.Time{}, 1); err != nil || len(short) != 1 {
			t.Fatalf("a page of one: %d entries, %v", len(short), err)
		}
	})

	t.Run("a revoked wallet unit cannot be unlocked", func(t *testing.T) {
		p := activated(t)
		if err := p.Revoke(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := p.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state != walletprovider.StateRevoked {
			t.Fatalf("state = %q, want %q", state, walletprovider.StateRevoked)
		}
		_, err = p.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
		if !errors.Is(err, walletprovider.ErrNotActivated) {
			t.Fatalf("got %v, want ErrNotActivated", err)
		}
	})
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
