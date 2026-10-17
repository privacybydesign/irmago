package services

import (
	"context"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/holdersigning"
	"github.com/privacybydesign/irmago/eudi/walletunit"
	"github.com/privacybydesign/irmago/walletprovider"
)

// holderSigner is the holdersigning.Signer OpenID4VP presentations are
// signed through. Software keys are signed with in process. Keys in the
// wallet provider's HSM are all signed with one call, after unlocking the
// wallet unit through the session in ctx, which asks for the PIN the first
// time; a presentation without such keys never asks.
type holderSigner struct {
	provider walletprovider.WalletProvider
}

// NewHolderSigner returns the signer for a wallet with the given wallet
// provider, which may be nil.
func NewHolderSigner(provider walletprovider.WalletProvider) holdersigning.Signer {
	return &holderSigner{provider: provider}
}

func (s *holderSigner) Sign(ctx context.Context, reqs []holdersigning.Request) ([][]byte, error) {
	sigs := make([][]byte, len(reqs))
	var external []walletprovider.SignRequest
	var externalAt []int
	for i, req := range reqs {
		if ref := req.Key.ExternalRef(); ref != "" {
			external = append(external, walletprovider.SignRequest{Ref: ref, SigningInput: req.Input})
			externalAt = append(externalAt, i)
			continue
		}
		sig, err := holdersigning.SignSoftware(req.Key, req.Input)
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}
	if len(external) == 0 {
		return sigs, nil
	}

	if s.provider == nil {
		return nil, fmt.Errorf("%d holder keys live in a wallet provider, but the wallet has none", len(external))
	}
	session := walletunit.SessionFrom(ctx)
	if session == nil {
		return nil, walletunit.ErrNoSession
	}
	// The provider is never told who the verifier is.
	unlocked, err := session.Unlocked(ctx, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB}, false)
	if err != nil {
		return nil, err
	}
	externalSigs, err := unlocked.Sign(ctx, external)
	if err != nil {
		return nil, fmt.Errorf("wallet provider failed to sign: %w", err)
	}
	if len(externalSigs) != len(external) {
		return nil, fmt.Errorf("wallet provider made %d signatures, want %d", len(externalSigs), len(external))
	}
	for j, i := range externalAt {
		sigs[i] = externalSigs[j]
	}
	return sigs, nil
}
