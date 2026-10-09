package client

import (
	"context"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/walletprovider"
)

// walletUnitActivationTimeout bounds a background activation.
const walletUnitActivationTimeout = 30 * time.Second

// activationGuard wraps the wallet's wallet provider so that activations never
// overlap: enrollment, a later PIN entry and an issuance can each start one,
// and two running at once would leave two accounts at the provider, one of
// them unreachable. An activation that finds the wallet unit already active
// does nothing. The guard also reports every activation to the app.
type activationGuard struct {
	walletprovider.WalletProvider
	handler ClientHandler
	mu      sync.Mutex
}

func (g *activationGuard) Activate(ctx context.Context, pin string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.State(ctx)
	if err != nil {
		return err
	}
	if state == walletprovider.StateActive {
		return nil
	}
	if err := g.WalletProvider.Activate(ctx, pin); err != nil {
		g.handler.WalletUnitActivationPending(err)
		return err
	}
	g.handler.WalletUnitActivated()
	return nil
}

// activateWalletUnitInBackground activates a wallet unit that is not activated
// yet with pin, a PIN the wallet has just enrolled with or verified at the
// keyshare server (docs/plans/wallet-provider-integration.md, decision 4). The
// outcome reaches the app through the guard's events.
func (client *Client) activateWalletUnitInBackground(pin string) {
	if client.walletProvider == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), walletUnitActivationTimeout)
		defer cancel()
		state, err := client.walletProvider.State(ctx)
		if err != nil || state != walletprovider.StateNotActivated {
			return
		}
		_ = client.walletProvider.Activate(ctx, pin)
	}()
}

// enrollmentPin remembers the PIN of a keyshare enrollment in progress, so the
// wallet unit can be activated with it once enrollment succeeds.
type enrollmentPin struct {
	mu  sync.Mutex
	pin string
}

func (e *enrollmentPin) set(pin string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pin = pin
}

// take returns the remembered PIN and forgets it.
func (e *enrollmentPin) take() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	pin := e.pin
	e.pin = ""
	return pin
}
