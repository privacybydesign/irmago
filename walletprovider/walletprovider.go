// Package walletprovider is the contract between the wallet and a wallet
// provider: the capability that holds the wallet's OpenID4VC holder keys in a
// remote HSM and vouches for the wallet unit (see CONTEXT.md, "Wallet
// provider"). The provider is implemented outside irmago and supplied to
// client.New; this package declares both directions of the contract — what
// the provider offers (WalletProvider) and what the wallet offers back to it
// (Host).
//
// The package imports only the standard library, and must keep doing so: the
// point of the split is that an implementation never has to import irmago, so
// no irmago refactor or dependency bump can break it (ADR 0010).
package walletprovider

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"
)

// Factory builds a provider around the host the wallet offers it. client.New
// calls it once, after the wallet's storage exists.
type Factory func(Host) (WalletProvider, error)

// Host is what the wallet offers the provider.
type Host interface {
	// Storage is the provider's own key-value store. It lives in the wallet's
	// encrypted database and is wiped along with the rest of the wallet.
	Storage() Storage
}

// ErrNotFound is returned by Storage for a key that holds no value, and by
// PossessionKey before the key has been created.
var ErrNotFound = errors.New("walletprovider: not found")

// Storage is a namespaced key-value store owned by the provider. Values are
// opaque to the wallet.
type Storage interface {
	// Get returns the value stored under key, or ErrNotFound.
	Get(key string) ([]byte, error)
	// Update runs fn atomically: either every write fn made is persisted, or,
	// when fn returns an error, none is.
	Update(fn func(tx StorageTx) error) error
}

// StorageTx is the view of Storage inside Update.
type StorageTx interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// PossessionKey is the wallet unit's possession key (U in SECDSA), held in
// secure hardware and never exported. The wallet never uses it: the app hands
// it to the provider when it builds the provider's Factory. It is declared
// here as the one shape the native implementations (Secure Enclave,
// StrongBox) and every provider agree on.
type PossessionKey interface {
	// Create mints the key, bound to the provider's challenge, replacing any
	// key created before. keyAttestation is the platform's certificate chain
	// over the new key (DER, leaf first); empty where the platform has none.
	Create(ctx context.Context, challenge []byte) (pub *ecdsa.PublicKey, keyAttestation [][]byte, err error)
	// PublicKey returns the public half, or ErrNotFound before Create.
	PublicKey() (*ecdsa.PublicKey, error)
	// SignDigest signs digest as is, without hashing it first (NONEwithECDSA),
	// and returns an ASN.1 DER ECDSA signature.
	SignDigest(digest []byte) (der []byte, err error)
	// AppAttestation returns the platform's integrity evidence over challenge,
	// naming the platform that produced it ("apple", "play_integrity", "open").
	AppAttestation(ctx context.Context, challenge []byte) (platform string, evidence []byte, err error)
	// Delete destroys the key. Deleting a key that does not exist is not an
	// error.
	Delete() error
}

// State is where the wallet unit stands with the provider.
type State string

const (
	// StateNotActivated: there is no wallet unit yet, or activation never
	// completed.
	StateNotActivated State = "not_activated"
	// StateActive: the wallet unit can be unlocked and used.
	StateActive State = "active"
	// StateRevoked: the wallet unit was deleted; it cannot be used again.
	StateRevoked State = "revoked"
)

// WalletProvider is implemented by the provider.
type WalletProvider interface {
	// State reports where the wallet unit stands.
	State(ctx context.Context) (State, error)
	// Activate sets up the wallet unit with the given PIN: it mints the
	// possession key and binds it and the PIN to a fresh account.
	Activate(ctx context.Context, pin string) error
	// Unlock presents the PIN for one session, scoped to one purpose. Returns
	// ErrNotActivated, *PinIncorrectError or *PinBlockedError when the PIN
	// cannot be used.
	//
	// Unlock must check the PIN with the provider before it returns, so that a
	// wrong or blocked PIN is reported here, where the wallet asks for it,
	// rather than by the first key generation or signature of the session.
	// Where the provider checks the PIN on every operation (SECDSA does), the
	// unlocked wallet unit keeps what it needs of the PIN — for SECDSA the
	// PIN-derived key, never the PIN itself — until Close.
	Unlock(ctx context.Context, pin string, scope Scope) (UnlockedWalletUnit, error)
	// RemoveKeys deletes holder keys. It needs no PIN: the possession key
	// suffices to delete what is the wallet's own. Refs the provider does not
	// know are ignored.
	RemoveKeys(ctx context.Context, refs []string) error
	// Revoke deletes the wallet unit and every key in it, with the possession
	// key only.
	Revoke(ctx context.Context) error
}

// Purpose is what an unlocked wallet unit may be used for.
type Purpose string

const (
	// PurposeIssuancePoP: generating holder keys and signing the OpenID4VCI
	// proofs of possession over them.
	PurposeIssuancePoP Purpose = "issuance-pop"
	// PurposeDisclosureKB: signing key binding JWTs and mdoc DeviceAuth.
	PurposeDisclosureKB Purpose = "disclosure-kb"
)

// Scope is what an unlock is for. The provider forwards it to its server,
// which records it in the wallet provider transaction log.
type Scope struct {
	Purpose Purpose
	// Counterparty is the credential issuer for issuance. Empty for
	// disclosure: the provider is never told who the verifier is.
	Counterparty string
	// CredentialTypes are the credential types being issued. Issuance only.
	CredentialTypes []string
}

// HolderKey is a holder key the provider generated.
type HolderKey struct {
	// Ref is the provider's name for the key: stored by the wallet with the
	// credential, and passed back to sign or remove it.
	Ref    string
	Public *ecdsa.PublicKey
}

// SignRequest is one signature to make.
type SignRequest struct {
	Ref string
	// SigningInput is exactly the bytes to sign: the JWS signing input for a
	// JWT, the COSE Sig_structure for an mdoc. The provider hashes it with
	// SHA-256 (ES256).
	SigningInput []byte
}

// UnlockedWalletUnit is a wallet unit unlocked for one session. Close it when
// the session ends; the provider may also expire it after a period without
// use, after which every call returns ErrUnlockExpired.
type UnlockedWalletUnit interface {
	// GenerateKeys creates n holder keys in the HSM.
	GenerateKeys(ctx context.Context, n int) ([]HolderKey, error)
	// Sign makes one signature per request, in order, each a raw 64-byte r‖s
	// ES256 signature as a JWS carries it.
	Sign(ctx context.Context, reqs []SignRequest) ([][]byte, error)
	// Close ends the unlock. Calling it more than once is harmless.
	Close()
}

var (
	// ErrNotActivated: the wallet unit has not been activated (or was revoked).
	ErrNotActivated = errors.New("walletprovider: wallet unit not activated")
	// ErrUnlockExpired: the unlocked wallet unit was closed or timed out; the
	// PIN must be asked for again.
	ErrUnlockExpired = errors.New("walletprovider: unlock expired")
)

// PinIncorrectError reports a wrong PIN. Remaining is how many attempts are
// left before the wallet unit blocks.
type PinIncorrectError struct {
	Remaining int
}

func (e *PinIncorrectError) Error() string {
	return fmt.Sprintf("walletprovider: incorrect PIN, %d attempts remaining", e.Remaining)
}

// PinBlockedError reports that too many wrong PINs were entered. Duration is
// how long until the PIN can be tried again, or zero when the block is
// permanent and the wallet unit can only be revoked and activated anew.
type PinBlockedError struct {
	Duration time.Duration
}

func (e *PinBlockedError) Error() string {
	if e.Duration == 0 {
		return "walletprovider: PIN blocked permanently"
	}
	return fmt.Sprintf("walletprovider: PIN blocked for %s", e.Duration)
}
