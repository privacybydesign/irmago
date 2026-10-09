package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/walletprovider"
)

// A PIN change spans the wallet provider and the keyshare servers, and
// neither can change with the other atomically
// (docs/plans/wallet-provider-integration.md, decision 13). The keyshare
// servers check the old PIN first; then the provider changes, then the
// keyshare servers. A keyshare failure rolls the provider back. Whenever the
// wallet cannot tell which PIN each side has, it records so, without any PIN,
// and asks the app to finish the change with both PINs (FinishPinChange).

// pinChangePendingKey marks a PIN change the wallet could not finish. Kept
// in the wallet's own table of the store it offers the provider, under a key
// the provider does not use, so it is wiped with the wallet.
const pinChangePendingKey = "client/pin-change-pending"

const pinChangeTimeout = 60 * time.Second

// pinChange holds the PINs of the change in flight, for rolling the provider
// back when the keyshare servers refuse; never persisted.
type pinChange struct {
	mu       sync.Mutex
	old, new string
	active   bool
}

func (p *pinChange) set(old, new string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.old, p.new, p.active = old, new, true
}

func (p *pinChange) take() (old, new string, active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old, new, active = p.old, p.new, p.active
	p.old, p.new, p.active = "", "", false
	return
}

// KeyshareChangePin changes the PIN at every keyshare server and, with a
// wallet provider, of the wallet unit. The outcome arrives through
// ChangePinSuccess, ChangePinIncorrect, ChangePinBlocked, ChangePinFailure or,
// when it could not be finished, ChangePinRecoveryRequired.
func (client *Client) KeyshareChangePin(oldPin, newPin string) {
	if client.walletProvider == nil {
		client.irmaClient.KeyshareChangePin(oldPin, newPin)
		return
	}
	go client.changePin(oldPin, newPin)
}

func (client *Client) changePin(oldPin, newPin string) {
	ctx, cancel := context.WithTimeout(context.Background(), pinChangeTimeout)
	defer cancel()

	// The keyshare servers' old PIN first, so a PIN they refuse never changes
	// the wallet unit's.
	for _, scheme := range client.irmaClient.EnrolledSchemeManagers() {
		success, attempts, blocked, err := client.irmaClient.KeyshareVerifyPin(oldPin, scheme)
		switch {
		case err != nil:
			client.handler.ChangePinFailure(scheme, err)
			return
		case !success && attempts > 0:
			client.handler.ChangePinIncorrect(scheme, attempts)
			return
		case !success:
			client.handler.ChangePinBlocked(scheme, blocked)
			return
		}
	}

	// A wallet unit still pending activation has no PIN yet: its activation
	// will use the new one.
	state, err := client.walletProvider.State(ctx)
	if err != nil {
		client.handler.ChangePinFailure(client.pinChangeScheme(), err)
		return
	}
	if state == walletprovider.StateActive {
		u, err := client.walletProvider.Unlock(ctx, oldPin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
		if err != nil {
			client.reportPinError(err)
			return
		}
		if err := client.markPinChangePending(); err != nil {
			u.Close()
			client.handler.ChangePinFailure(client.pinChangeScheme(), err)
			return
		}
		if err := u.ChangePin(ctx, newPin); err != nil {
			// Whether the provider changed before failing cannot be told from
			// here; FinishPinChange finds out.
			irma.Logger.Warnf("wallet unit PIN change failed: %v", err)
			client.handler.ChangePinRecoveryRequired()
			return
		}
	}

	client.pinChange.set(oldPin, newPin)
	client.irmaClient.KeyshareChangePin(oldPin, newPin)
}

// keysharePinChangeEnded finishes a PIN change once the keyshare servers
// reported. Runs before the app hears of the outcome.
func (client *Client) keysharePinChangeEnded(success bool) {
	oldPin, newPin, active := client.pinChange.take()
	if !active {
		return
	}
	if success {
		client.clearPinChangePending()
		return
	}
	// The keyshare servers kept the old PIN; so must the wallet unit.
	ctx, cancel := context.WithTimeout(context.Background(), pinChangeTimeout)
	defer cancel()
	state, err := client.walletProvider.State(ctx)
	if err == nil && state == walletprovider.StateActive {
		err = client.changeWalletUnitPin(ctx, newPin, oldPin)
	}
	if err != nil {
		irma.Logger.Warnf("could not roll back the wallet unit PIN: %v", err)
		client.handler.ChangePinRecoveryRequired()
		return
	}
	client.clearPinChangePending()
}

// PinChangeRecoveryRequired reports whether a PIN change was left unfinished,
// so the app can ask for both PINs and call FinishPinChange, also after a
// restart.
func (client *Client) PinChangeRecoveryRequired() bool {
	if client.walletProvider == nil {
		return false
	}
	_, err := client.pinChangeStore().Get(pinChangePendingKey)
	return err == nil
}

// FinishPinChange completes an unfinished PIN change, given the PIN before and
// the PIN after it. Each side is brought to newPin from whichever PIN it
// turns out to have. Reports like KeyshareChangePin.
func (client *Client) FinishPinChange(oldPin, newPin string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), pinChangeTimeout)
		defer cancel()
		if client.walletProvider != nil {
			state, err := client.walletProvider.State(ctx)
			if err != nil {
				client.handler.ChangePinFailure(client.pinChangeScheme(), err)
				return
			}
			if state == walletprovider.StateActive {
				if err := client.bringWalletUnitTo(ctx, oldPin, newPin); err != nil {
					client.reportPinError(err)
					return
				}
			}
		}

		// The keyshare servers: done if they already accept the new PIN.
		done := true
		for _, scheme := range client.irmaClient.EnrolledSchemeManagers() {
			success, _, _, err := client.irmaClient.KeyshareVerifyPin(newPin, scheme)
			if err != nil || !success {
				done = false
			}
		}
		if done {
			client.clearPinChangePending()
			client.handler.ChangePinSuccess()
			return
		}
		client.pinChange.set(oldPin, newPin)
		client.irmaClient.KeyshareChangePin(oldPin, newPin)
	}()
}

// bringWalletUnitTo leaves the wallet unit with newPin, whether it has that
// PIN already or still oldPin.
func (client *Client) bringWalletUnitTo(ctx context.Context, oldPin, newPin string) error {
	u, err := client.walletProvider.Unlock(ctx, newPin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
	if err == nil {
		u.Close()
		return nil
	}
	if _, incorrect := errors.AsType[*walletprovider.PinIncorrectError](err); !incorrect {
		return err
	}
	return client.changeWalletUnitPin(ctx, oldPin, newPin)
}

func (client *Client) changeWalletUnitPin(ctx context.Context, fromPin, toPin string) error {
	u, err := client.walletProvider.Unlock(ctx, fromPin, walletprovider.Scope{Purpose: walletprovider.PurposePinChange})
	if err != nil {
		return err
	}
	return u.ChangePin(ctx, toPin)
}

// reportPinError tells the app about a PIN the wallet unit refused.
func (client *Client) reportPinError(err error) {
	scheme := client.pinChangeScheme()
	if incorrect, ok := errors.AsType[*walletprovider.PinIncorrectError](err); ok {
		client.handler.ChangePinIncorrect(scheme, incorrect.Remaining)
		return
	}
	if blocked, ok := errors.AsType[*walletprovider.PinBlockedError](err); ok {
		client.handler.ChangePinBlocked(scheme, int(blocked.Duration/time.Second))
		return
	}
	client.handler.ChangePinFailure(scheme, err)
}

// pinChangeScheme is the scheme a PIN change event not about a keyshare
// server is reported under: the wallet's (first) keyshare scheme.
func (client *Client) pinChangeScheme() irma.SchemeManagerIdentifier {
	if schemes := client.irmaClient.EnrolledSchemeManagers(); len(schemes) > 0 {
		return schemes[0]
	}
	return irma.SchemeManagerIdentifier{}
}

func (client *Client) pinChangeStore() walletprovider.Storage {
	return db.NewWalletProviderStorage(client.eudiStorage.Db())
}

func (client *Client) markPinChangePending() error {
	return client.pinChangeStore().Update(func(tx walletprovider.StorageTx) error {
		return tx.Put(pinChangePendingKey, []byte("1"))
	})
}

func (client *Client) clearPinChangePending() {
	if err := client.pinChangeStore().Update(func(tx walletprovider.StorageTx) error {
		return tx.Delete(pinChangePendingKey)
	}); err != nil {
		irma.Logger.Warnf("could not clear the pending PIN change: %v", err)
	}
}
