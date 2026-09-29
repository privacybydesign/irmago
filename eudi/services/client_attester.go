package services

import (
	"context"
	"crypto/ecdsa"

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

// Attest asks the provider for a WIA binding key.
func (a *WalletProviderClientAttester) Attest(ctx context.Context, key *ecdsa.PublicKey) (string, error) {
	if a.provider == nil {
		return "", walletprovider.ErrNotActivated
	}
	wia, err := a.provider.InstanceAttestation(ctx, key)
	if err != nil {
		return "", err
	}
	return string(wia), nil
}
