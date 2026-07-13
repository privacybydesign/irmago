package openid4vci

import (
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

// HolderKeyBinder creates holder binding key pairs and the matching OpenID4VCI
// proofs of possession for an issuance session. The default implementation
// (services.HolderBindingKeyService) generates software ECDSA keys and stores
// them; an alternative implementation can delegate to an external secure device
// (WSCA/HSM) so the holder private key never enters this process.
//
// The returned publicKeyIdentifiers must be persisted such that
// credential_service can match each issued credential's cnf claim to one of
// them (by JWK thumbprint or DID URL) and link it to the stored instance.
type HolderKeyBinder interface {
	CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) (publicKeyIdentifiers []models.PublicHolderBindingKey, proofsOut []string, err error)
	// RemoveKeys deletes previously created keys by their storage IDs. Used to
	// roll back generated keys when an issuance session fails.
	RemoveKeys(ids []datatypes.UUID) error
}

// ClientOption customizes a Client at construction time.
type ClientOption func(*Client)

// WithHolderKeyBinder overrides the default (software) holder key binder used
// during OpenID4VCI issuance — e.g. to bind holder keys to a WSCA. When not
// set, the session falls back to the storage-backed software binder.
func WithHolderKeyBinder(b HolderKeyBinder) ClientOption {
	return func(c *Client) { c.holderKeyBinder = b }
}
