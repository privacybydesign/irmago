package services

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/holdersigning"
	"github.com/privacybydesign/irmago/eudi/storage/db"
)

// mdocDeviceKeyResolver resolves the device key an mdoc presentation is signed
// with from the stored device keys, satisfying the DeviceKeys interface
// mdoc_dcql declares. It is the mdoc counterpart of
// holderBindingKeyService.ResolveHolderKey: a software key resolves to its
// private key, a key in the wallet provider's HSM to the provider's reference,
// and the holdersigning.Signer the presentation is signed through handles
// either.
type mdocDeviceKeyResolver struct {
	store db.MdocDeviceKeyStore
}

// NewMdocDeviceKeyResolver creates the storage-backed device key resolver to
// hand to mdoc_dcql.NewMdocDcqlHandler.
func NewMdocDeviceKeyResolver(store db.MdocDeviceKeyStore) *mdocDeviceKeyResolver {
	return &mdocDeviceKeyResolver{store: store}
}

// ResolveDeviceKey looks the device key up by the JWK thumbprint of its public
// half, which is the identity MdocKeyService stored it under at mint time and
// mdocCredentialFormatParser recorded for the credential at issuance (see
// ParsedMdoc.DeviceKeyThumbprint). All three derive it with
// jwkThumbprintFromECDSAPublicKey, so the write and the reads cannot drift into
// computing the thumbprint differently.
func (r *mdocDeviceKeyResolver) ResolveDeviceKey(deviceKey *ecdsa.PublicKey) (holdersigning.Key, error) {
	if deviceKey == nil {
		return holdersigning.Key{}, fmt.Errorf("credential names no device key to sign with")
	}

	thumbprint, err := jwkThumbprintFromECDSAPublicKey(deviceKey)
	if err != nil {
		return holdersigning.Key{}, fmt.Errorf("compute device key thumbprint: %w", err)
	}

	stored, err := r.store.GetByThumbprint(thumbprint)
	if err != nil {
		// Worth distinguishing from a signing failure: the wallet holds a
		// credential bound to a key it has no private half for, which is a
		// credential it can never present rather than a presentation that went
		// wrong once.
		return holdersigning.Key{}, fmt.Errorf("no device key stored for thumbprint %s: %w", thumbprint, err)
	}

	if ref := stored.ProviderKeyRef(); ref != "" {
		return holdersigning.External(ref), nil
	}
	privateKey, err := decodePKCS8PrivateKey(stored.PrivateKey)
	if err != nil {
		return holdersigning.Key{}, fmt.Errorf("decode stored device key %s: %w", stored.ID, err)
	}
	return holdersigning.Software(privateKey), nil
}
