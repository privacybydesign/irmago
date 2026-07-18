package wallet

import "github.com/privacybydesign/irmago/eudi/holderkeys"

// The holder-key seam (HolderSigner + the KB-JWT binder bridge) moved to the
// CGO-free eudi/holderkeys package, so consumers — e.g. the WSCA adapter in the
// wallet-provider module, or a server-side (Postgres) holder — can implement and
// wire it without importing this package, which pulls in sqlcipher (cgo) via
// wallet.New. These aliases preserve the eudi/wallet API for existing callers.
type (
	HolderSigner         = holderkeys.HolderSigner
	SoftwareHolderSigner = holderkeys.SoftwareHolderSigner
)

// NewSoftwareHolderSigner returns an in-memory HolderSigner (default behavior).
var NewSoftwareHolderSigner = holderkeys.NewSoftwareHolderSigner
