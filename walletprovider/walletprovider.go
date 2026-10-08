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
	// RemoveKeys deletes holder keys. It needs neither the PIN nor a
	// connection: the provider records the refs and removes the keys with the
	// next unlock, which proves the PIN, so a wallet can delete credentials
	// offline. Until then the keys are only unreachable, not gone. Refs the
	// provider does not know are ignored.
	RemoveKeys(ctx context.Context, refs []string) error
	// Revoke deletes the wallet unit and every key in it, with the possession
	// key only.
	Revoke(ctx context.Context) error
	// KeyProtection is what the provider's key attestations say about how its
	// holder keys are protected, known without the PIN, so the wallet can tell
	// before asking the user anything whether an issuer's requirements can be
	// met.
	KeyProtection(ctx context.Context) (KeyProtection, error)
}

// KeyProtection is how strongly holder keys are protected, as ISO 18045
// attack potential resistance levels ("iso_18045_high", "iso_18045_moderate",
// "iso_18045_enhanced-basic", "iso_18045_basic"; OpenID4VCI 1.0 Appendix
// D.2). Each is what the key attestation claims (key_storage,
// user_authentication), empty when it claims nothing.
type KeyProtection struct {
	// KeyStorage is the resistance of the key storage component and its keys.
	KeyStorage []string
	// UserAuthentication is the resistance of the user authentication needed
	// to use the keys.
	UserAuthentication []string
}

// KeyAttestationRequest asks GenerateKeys for a key attestation over the keys
// it generates.
type KeyAttestationRequest struct {
	// Nonce is the credential issuer's c_nonce, which the attestation carries
	// to show it is fresh; empty when the issuer has no nonce endpoint.
	Nonce string
}

// Purpose is what an unlocked wallet unit may be used for.
type Purpose string

const (
	// PurposeIssuancePoP: generating holder keys and signing the OpenID4VCI
	// proofs of possession over them.
	PurposeIssuancePoP Purpose = "issuance-pop"
	// PurposeDisclosureKB: signing key binding JWTs and mdoc DeviceAuth.
	PurposeDisclosureKB Purpose = "disclosure-kb"
	// PurposePinChange: changing the PIN; see UnlockedWalletUnit.ChangePin.
	PurposePinChange Purpose = "pin-change"
	// PurposeTransactionLog: reading the wallet provider transaction log.
	PurposeTransactionLog Purpose = "transaction-log"
)

// Operation is what the provider did in a logged transaction.
type Operation string

const (
	OperationActivate     Operation = "activate"
	OperationUnlock       Operation = "unlock"
	OperationGenerateKeys Operation = "generate-keys"
	OperationSign         Operation = "sign"
	OperationRemoveKeys   Operation = "remove-keys"
	OperationChangePin    Operation = "change-pin"
	// OperationAttestInstance is issuing a wallet instance attestation.
	OperationAttestInstance Operation = "attest-instance"
	// OperationRejected is a request the provider refused for a wrong or
	// blocked PIN, before it could tell what was asked. Its entries are how
	// the user sees someone trying their PIN.
	OperationRejected Operation = "rejected"
	// OperationOther is any operation without a name of its own here.
	OperationOther Operation = "other"
)

// Transaction is one entry of the wallet provider transaction log: what the
// provider did for this wallet unit (CONTEXT.md, "Wallet provider transaction
// log"). It never names the verifier of a disclosure; the provider is never
// told.
type Transaction struct {
	ID        string
	Time      time.Time
	Operation Operation
	// Purpose is the declared purpose of a signature, when the provider
	// records one.
	Purpose Purpose
	// Counterparty and CredentialType are the issuer and credential type of an
	// issuance signature, when recorded.
	Counterparty   string
	CredentialType string
	Succeeded      bool
}

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
	// GenerateKeys creates n holder keys in the HSM. With attest non-nil it
	// also returns one key attestation (KA, a key-attestation+jwt as in
	// OpenID4VCI 1.0 Appendix D) over exactly those keys, claiming the
	// protection KeyProtection reports; otherwise keyAttestation is nil. A key
	// attestation only ever covers keys generated in the same call.
	GenerateKeys(ctx context.Context, n int, attest *KeyAttestationRequest) (keys []HolderKey, keyAttestation []byte, err error)
	// Sign makes one signature per request, in order, each a raw 64-byte r‖s
	// ES256 signature as a JWS carries it.
	Sign(ctx context.Context, reqs []SignRequest) ([][]byte, error)
	// Transactions returns the wallet unit's transaction log, newest first:
	// at most max entries, and only those before the given time unless it is
	// zero.
	Transactions(ctx context.Context, before time.Time, max int) ([]Transaction, error)
	// InstanceAttestation returns a wallet instance attestation (WIA, TS3)
	// binding key: the provider's statement that the wallet holding key is a
	// genuine wallet whose wallet unit is not revoked, as an OAuth client
	// attestation JWT (oauth-client-attestation+jwt) for the wallet to
	// authenticate itself to an authorization server with. Like every use
	// of the wallet unit but revoking it, it needs the PIN. The wallet asks
	// for one per issuance session, and only from an authorization server
	// that asks for client attestation.
	//
	// Returns ErrAttestationRefused when the provider will not vouch for
	// this wallet unit now.
	InstanceAttestation(ctx context.Context, key *ecdsa.PublicKey) ([]byte, error)
	// ChangePin replaces the PIN the wallet unit was unlocked with by newPin.
	// The holder keys stay. The unlocked wallet unit is closed afterwards:
	// what it kept of the old PIN no longer works.
	ChangePin(ctx context.Context, newPin string) error
	// Close ends the unlock. Calling it more than once is harmless.
	Close()
}

var (
	// ErrNotActivated: the wallet unit has not been activated (or was revoked).
	ErrNotActivated = errors.New("walletprovider: wallet unit not activated")
	// ErrUnlockExpired: the unlocked wallet unit was closed or timed out; the
	// PIN must be asked for again.
	ErrUnlockExpired = errors.New("walletprovider: unlock expired")
	// ErrAttestationRefused: the provider will not vouch for this wallet unit
	// now, for instance while its PIN is blocked or when its device could not
	// be attested at activation.
	ErrAttestationRefused = errors.New("walletprovider: attestation refused")
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
