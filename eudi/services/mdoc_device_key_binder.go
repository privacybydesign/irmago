package services

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db"
)

// mdocDeviceKeyBinder resolves the device key an mdoc presentation is signed
// with from the stored device keys, satisfying the DeviceKeyBinder interface
// mdoc_dcql declares. It is the software counterpart of
// sdjwt.DefaultKeyBinder: the device private key lives in this process, read
// from storage on demand.
//
// The point of the seam is what can replace it. An implementation backed by a
// WSCA/HSM or by the platform's key store (StrongBox, TrustZone, the Secure
// Enclave) resolves the same device key to a mdoc.Holder whose private half is a
// key handle rather than bytes -- see mdoc.NewHolderFromSigner -- and the wallet
// then signs presentations without the key ever entering the process. Nothing
// above this type would change; the handler is handed a DeviceKeyBinder and
// never sees key material either way.
type mdocDeviceKeyBinder struct {
	store db.MdocDeviceKeyStore
}

// NewMdocDeviceKeyBinder creates the storage-backed device key binder to hand to
// mdoc_dcql.NewMdocDcqlHandler.
func NewMdocDeviceKeyBinder(store db.MdocDeviceKeyStore) *mdocDeviceKeyBinder {
	return &mdocDeviceKeyBinder{store: store}
}

// HolderForDeviceKey looks the device key up by the JWK thumbprint of its public
// half, which is the identity MdocKeyService stored it under at mint time and
// mdocCredentialFormatParser recorded for the credential at issuance (see
// ParsedMdoc.DeviceKeyThumbprint). All three derive it with
// jwkThumbprintFromECDSAPublicKey, so the write and the reads cannot drift into
// computing the thumbprint differently.
func (b *mdocDeviceKeyBinder) HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.Holder, error) {
	if deviceKey == nil {
		return nil, fmt.Errorf("credential names no device key to sign with")
	}

	thumbprint, err := jwkThumbprintFromECDSAPublicKey(deviceKey)
	if err != nil {
		return nil, fmt.Errorf("compute device key thumbprint: %w", err)
	}

	stored, err := b.store.GetByThumbprint(thumbprint)
	if err != nil {
		// Worth distinguishing from a signing failure: the wallet holds a
		// credential bound to a key it has no private half for, which is a
		// credential it can never present rather than a presentation that went
		// wrong once.
		return nil, fmt.Errorf("no device key stored for thumbprint %s: %w", thumbprint, err)
	}

	privateKey, err := decodePKCS8PrivateKey(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode stored device key %s: %w", stored.ID, err)
	}

	return mdoc.NewHolderFromPrivateKey(privateKey)
}
