package services

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
)

// MdocCredentialService stores ISO/IEC 18013-5 mdoc credentials.
// See the package documentation in the file's previous revision.
type MdocCredentialService interface {
	StoreMdocCredential(issuerSignedCBOR []byte, deviceKey *ecdsa.PrivateKey) (*models.CredentialBatch, error)
}

type mdocCredentialService struct {
	credentialStore storage.CredentialStore
}

// NewMdocCredentialService returns an MdocCredentialService backed by the
// supplied storage.
func NewMdocCredentialService(s storage.Storage) MdocCredentialService {
	return &mdocCredentialService{credentialStore: storage.NewCredentialStore(s)}
}

func (s *mdocCredentialService) StoreMdocCredential(issuerSignedCBOR []byte, deviceKey *ecdsa.PrivateKey) (*models.CredentialBatch, error) {
	issuerSigned, err := mdoc.ParseIssuerSigned(issuerSignedCBOR)
	if err != nil {
		return nil, fmt.Errorf("mdoc credential service: parse IssuerSigned: %w", err)
	}
	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	if err != nil {
		return nil, fmt.Errorf("mdoc credential service: parse MSO: %w", err)
	}

	projection, err := buildMdocAttributeProjection(issuerSigned.Namespaces)
	if err != nil {
		return nil, fmt.Errorf("mdoc credential service: project attributes: %w", err)
	}
	// json.Marshal sorts map keys, so the byte representation is stable for a
	// given {docType, ns, element, value} set.
	projectionJSON, err := json.Marshal(projection)
	if err != nil {
		return nil, err
	}

	hash := hashForMdoc(mso.DocType, projectionJSON)

	issuerIdentity, err := extractMdocIssuerIdentity(issuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("mdoc credential service: extract issuer identity: %w", err)
	}

	keyModel, err := ecdsaToHolderBindingKey(deviceKey)
	if err != nil {
		return nil, fmt.Errorf("mdoc credential service: encode device key: %w", err)
	}

	batch := &models.CredentialBatch{
		IssuerURL:                issuerIdentity,
		VerifiableCredentialType: mso.DocType,
		Format:                   models.CredentialFormatMdoc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    projectionJSON,
		IssuedAt:                 mso.ValidityInfo.Signed.UTC(),
		ExpiresAt:                datatypes.NullTime{V: mso.ValidityInfo.ValidUntil.UTC(), Valid: true},
		NotBefore:                datatypes.NullTime{V: mso.ValidityInfo.ValidFrom.UTC(), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         issuerIdentity,
		Instances: []models.IssuedCredentialInstance{
			{
				RawCredential:    append([]byte(nil), issuerSignedCBOR...),
				HolderBindingKey: keyModel,
			},
		},
	}

	if err := s.credentialStore.StoreBatch(batch); err != nil {
		return nil, fmt.Errorf("mdoc credential service: store batch: %w", err)
	}
	return batch, nil
}

// buildMdocAttributeProjection turns the parsed namespaces into a nested
// map[namespace]map[element]value, decoding CBOR element values into native
// Go types where possible. The byte-wise CBOR form is preserved elsewhere
// (RawCredential) so this projection is purely for UI/consent display and
// for deterministic hashing.
func buildMdocAttributeProjection(ns mdoc.IssuerNamespaces) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(ns))
	for name, items := range ns {
		inner := make(map[string]any, len(items))
		for _, it := range items {
			var v any
			if err := cbor.Unmarshal(it.ElementValue, &v); err != nil {
				// Fallback: keep as hex so display still renders and hashing
				// stays deterministic.
				v = fmt.Sprintf("%x", it.ElementValue)
			}
			inner[it.ElementIdentifier] = v
		}
		out[name] = inner
	}
	return out, nil
}

// hashForMdoc returns a base64url SHA-256 digest that dedups on content (same
// docType + same disclosed attribute values ⇒ same hash). This mirrors the
// SD-JWT-VC dedup hash but keyed on the mdoc-native fields.
func hashForMdoc(docType string, projectionJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(docType))
	h.Write([]byte{0})
	h.Write(projectionJSON)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// extractMdocIssuerIdentity derives a stable issuer identifier from the DS
// certificate's subject Common Name. mdoc has no native "issuer URL"
// equivalent to the SD-JWT `iss` claim, but every credential carries a DS
// cert in IssuerAuth's x5chain header — good enough for UI display and
// DCQL TrustedAuthority bookkeeping until a proper trust-list lookup exists.
func extractMdocIssuerIdentity(auth mdoc.IssuerAuth) (string, error) {
	chain, err := auth.X5Chain()
	if err != nil {
		return "", err
	}
	if len(chain) == 0 {
		return "", errors.New("IssuerAuth has no x5chain")
	}
	cn := chain[0].Subject.CommonName
	if cn == "" {
		return "", errors.New("DS certificate subject has no Common Name")
	}
	return cn, nil
}

// ecdsaToHolderBindingKey encodes a P-256 device private key into the shared
// HolderBindingKey row. PublicKeyThumbprint is the base64url SHA-256 of the
// uncompressed EC point — the simplest form the storage unique index can key
// on without us having to port a JWK-thumbprint implementation.
func ecdsaToHolderBindingKey(priv *ecdsa.PrivateKey) (*models.HolderBindingKey, error) {
	if priv == nil {
		return nil, errors.New("device key is nil")
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}

	const coordSize = 32
	uncompressed := make([]byte, 1+2*coordSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+coordSize], padLeftBytes(priv.PublicKey.X.Bytes(), coordSize))
	copy(uncompressed[1+coordSize:], padLeftBytes(priv.PublicKey.Y.Bytes(), coordSize))
	sum := sha256.Sum256(uncompressed)
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])

	curveName := priv.Curve.Params().Name // "P-256" for elliptic.P256()
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: datatypes.NullString{V: thumbprint, Valid: true},
		PrivateKey:          der,
		ECDSA:               &models.ECDSAKeyMetadata{CurveName: curveName},
	}, nil
}

func padLeftBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
