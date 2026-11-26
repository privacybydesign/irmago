package services

import (
	"context"
	"crypto/ecdsa"

	"github.com/privacybydesign/irmago/eudi/walletunit"
	"github.com/privacybydesign/irmago/walletprovider"
)

// WalletProviderClientAttester gets the wallet instance attestations an
// OpenID4VCI session authenticates to an authorization server with from the
// wallet provider (openid4vci.ClientAttester). Without a provider there is
// none to get.
type WalletProviderClientAttester struct {
	provider walletprovider.WalletProvider
}

// NewClientAttester returns the attester over provider, which may be nil.
func NewClientAttester(provider walletprovider.WalletProvider) *WalletProviderClientAttester {
	return &WalletProviderClientAttester{provider: provider}
}

// Available reports whether the wallet has an active wallet unit, from the
// provider's local state.
func (a *WalletProviderClientAttester) Available(ctx context.Context) bool {
	if a.provider == nil {
		return false
	}
	state, err := a.provider.State(ctx)
	return err == nil && state == walletprovider.StateActive
}

// Attest asks the provider for a WIA binding key. That needs the PIN, so it
// unlocks through the session in ctx, with the scope the issuance session's
// key generation unlocks with: the user is asked for the PIN once, for both.
func (a *WalletProviderClientAttester) Attest(ctx context.Context, key *ecdsa.PublicKey, credentialIssuer string) (string, error) {
	if a.provider == nil {
		return "", walletprovider.ErrNotActivated
	}
	session := walletunit.SessionFrom(ctx)
	if session == nil {
		return "", walletunit.ErrNoSession
	}
	unlocked, err := session.Unlocked(ctx, IssuanceScope(credentialIssuer), false)
	if err != nil {
		return "", err
	}
	wia, err := unlocked.InstanceAttestation(ctx, key)
	if err != nil {
		return "", err
	}
	return string(wia), nil
}
