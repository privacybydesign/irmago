package services

import (
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
type HolderKeyBinder interface {
	CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) (publicKeyIdentifiers []models.PublicHolderBindingKey, proofsOut []string, err error)

	// RemoveKeys deletes previously created keys by their storage IDs. Used to
	// roll back generated keys when an issuance session fails.
	RemoveKeys(ids []datatypes.UUID) error
}
