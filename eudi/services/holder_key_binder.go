package services

import (
	"context"

	"github.com/privacybydesign/irmago/walletprovider"

	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

// HolderKeyBinder creates the key pairs an issuance binds credentials to, and
// the matching OpenID4VCI proofs of possession. One implementation per
// credential format, because each format keeps its keys in its own table:
// HolderBindingKeyService for SD-JWT VC (holder binding keys, matched by cnf),
// MdocKeyService for mso_mdoc (device keys, matched by the COSE key in the
// MSO). An alternative implementation can delegate to an external secure
// device (WSCA/HSM, StrongBox, the Secure Enclave) so the private key never
// enters this process.
//
// The returned publicKeyIdentifiers are what the format's store matches each
// issued credential against to link it to its stored key.
//
// ctx is the issuance session's: a binder that has to ask the user something
// before it can mint keys (a wallet provider's PIN) finds the means to in it.
//
// With attest non-nil the keys come with a key attestation (KA) over them, as
// the issuer requires: carried in every proof's key_attestation header, or,
// with attest.AsProof, as the one proof itself. Only keys a wallet provider
// holds can be attested.
type HolderKeyBinder interface {
	CreateKeyPairsWithProofs(ctx context.Context, num uint, proofBuilder proofs.ProofBuilder, attest *KeyAttestationOptions) (publicKeyIdentifiers []models.PublicHolderBindingKey, proofsOut []string, err error)

	// KeyProtection reports how the keys this binder would mint now are
	// protected, as their key attestation would claim; false when they could
	// not be attested (software keys, or a wallet unit that is not active).
	// It asks nobody, so it can be checked before the user is asked anything.
	KeyProtection(ctx context.Context) (walletprovider.KeyProtection, bool)

	// RemoveKeys deletes previously created keys by their storage IDs. Used to
	// roll back generated keys when an issuance session fails.
	RemoveKeys(ids []datatypes.UUID) error
}

// KeyAttestationOptions asks CreateKeyPairsWithProofs for a key attestation
// over the keys it mints.
type KeyAttestationOptions struct {
	// Nonce is the issuer's c_nonce, empty without a nonce endpoint.
	Nonce string
	// AsProof sends the key attestation as the proof (the attestation proof
	// type, OpenID4VCI 1.0 Appendix F.3): the keys then sign nothing. Otherwise
	// every jwt proof carries it in its key_attestation header.
	AsProof bool
}

// providerKeyProtection is KeyProtection for binders that mint in provider,
// which may be nil.
func providerKeyProtection(ctx context.Context, provider walletprovider.WalletProvider) (walletprovider.KeyProtection, bool) {
	if provider == nil {
		return walletprovider.KeyProtection{}, false
	}
	if state, err := provider.State(ctx); err != nil || state != walletprovider.StateActive {
		return walletprovider.KeyProtection{}, false
	}
	protection, err := provider.KeyProtection(ctx)
	if err != nil {
		return walletprovider.KeyProtection{}, false
	}
	return protection, true
}
