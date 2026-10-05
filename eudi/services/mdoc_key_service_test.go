package services

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func testProofBuilder(method proofs.CryptographicBindingMethod) proofs.ProofBuilder {
	nonce := "nonce-123"
	return proofs.NewJwtProofBuilder(
		"https://wallet.example.com",
		"https://issuer.example.com",
		jwa.ES256(),
		&nonce,
		jwt.ClockFunc(func() time.Time { return time.Unix(1_760_000_000, 0) }),
		method,
	)
}

// Whatever binding method the proof uses, an mdoc device key is stored under
// its thumbprint and nothing else: that is the identity the MSO's COSE key
// yields at issuance and at presentation. This is what retires the
// DID-derivation workaround the shared key table forced on mdoc.
func TestMdocKeyService_StoresThumbprintForEveryBindingMethod(t *testing.T) {
	for _, method := range []proofs.CryptographicBindingMethod{
		proofs.CryptographicBindingMethod_JWK,
		proofs.CryptographicBindingMethod_DID_KEY,
		proofs.CryptographicBindingMethod_DID_JWK,
	} {
		t.Run(string(method), func(t *testing.T) {
			d := newTestHolderDB(t)
			keys := db.NewMdocDeviceKeyStore(d)
			svc := NewMdocKeyService(keys)

			identifiers, proofStrings, err := svc.CreateKeyPairsWithProofs(3, testProofBuilder(method))
			require.NoError(t, err)
			require.Len(t, identifiers, 3)
			require.Len(t, proofStrings, 3)

			for _, id := range identifiers {
				require.False(t, id.ID.IsNil())
				require.NotNil(t, id.PublicKeyThumbprint, "every mdoc device key is identified by thumbprint")
				require.Nil(t, id.DidUrl, "no DID URL is recorded for a device key")

				stored, err := keys.GetByThumbprint(*id.PublicKeyThumbprint)
				require.NoError(t, err)
				require.Equal(t, id.ID, stored.ID)
				require.Equal(t, "P-256", stored.Curve)
				require.NotEmpty(t, stored.PrivateKey)
				require.Nil(t, stored.MdocBatchInstanceID, "minted keys are unbound until the credential is stored")
			}
		})
	}
}

func TestMdocKeyService_RemoveKeys(t *testing.T) {
	d := newTestHolderDB(t)
	keys := db.NewMdocDeviceKeyStore(d)
	svc := NewMdocKeyService(keys)

	identifiers, _, err := svc.CreateKeyPairsWithProofs(2, testProofBuilder(proofs.CryptographicBindingMethod_JWK))
	require.NoError(t, err)

	require.NoError(t, svc.RemoveKeys([]datatypes.UUID{identifiers[0].ID}))
	_, err = keys.GetByThumbprint(*identifiers[0].PublicKeyThumbprint)
	require.ErrorIs(t, err, db.ErrNotFound)
	_, err = keys.GetByThumbprint(*identifiers[1].PublicKeyThumbprint)
	require.NoError(t, err)

	var n int64
	require.NoError(t, d.Model(&models.MdocDeviceKey{}).Count(&n).Error)
	require.Equal(t, int64(1), n)
}
