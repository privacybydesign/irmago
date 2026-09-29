package providertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

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
	unlock := func(t *testing.T, p walletprovider.WalletProvider, purpose walletprovider.Purpose) walletprovider.UnlockedWalletUnit {
		t.Helper()
		u, err := p.Unlock(ctx, pin, walletprovider.Scope{Purpose: purpose, Counterparty: "https://issuer.example"})
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
