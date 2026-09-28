package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/holdersigning"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/walletunit"
	"github.com/privacybydesign/irmago/walletprovider"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// HolderBindingKeyService manages holder binding keys for both issuance
// (CreateKeyPairsWithProofs) and disclosure (ResolveHolderKey).
type HolderBindingKeyService interface {
	sdjwt.KeyBindingStorage
	CreateKeyPairsWithProofs(ctx context.Context, num uint, proofBuilder proofs.ProofBuilder) (publicKeyIdentifiers []models.PublicHolderBindingKey, proofs []string, err error)
	RemoveKeys(ids []datatypes.UUID) error
	ResolveHolderKey(pubKey jwk.Key) (holdersigning.Key, error)
}

type holderBindingKeyService struct {
	store db.HolderBindingKeyStore

	// provider is the wallet's wallet provider, nil when it has none. With a
	// provider, new keys are always minted in its HSM.
	provider walletprovider.WalletProvider
}

// keyTuple is one freshly minted holder key: a software key (privKey set) or
// a wallet provider key (ref set).
type keyTuple struct {
	privKey   *ecdsa.PrivateKey
	ref       string
	pub       *ecdsa.PublicKey
	jwkPubKey jwk.Key
	didUrl    *string
}

// backend is where the key's private half lives, and privateKeyBytes what the
// key row stores for it.
func (k keyTuple) backend() models.KeyBackend {
	if k.ref != "" {
		return models.KeyBackendWalletProvider
	}
	return models.KeyBackendSoftware
}

func (k keyTuple) privateKeyBytes() ([]byte, error) {
	if k.ref != "" {
		return []byte(k.ref), nil
	}
	b, err := x509.MarshalPKCS8PrivateKey(k.privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to bytes: %v", err)
	}
	return b, nil
}

// NewHolderBindingKeyService returns the SD-JWT VC holder key service. With a
// wallet provider (non-nil provider) it mints keys in the provider's HSM,
// otherwise in software.
func NewHolderBindingKeyService(d *gorm.DB, provider walletprovider.WalletProvider) *holderBindingKeyService {
	return &holderBindingKeyService{
		store:    db.NewHolderBindingKeyStore(d),
		provider: provider,
	}
}

// CreateKeyPairsWithProofs creates the specified number of ECDSA key pairs, stores the private keys, and returns the corresponding proofs built using the provided proof builder.
// The publicKeyIdentifiers are the public identifiers (either DIDs or JWK thumbprints) that can be used in the credential's proof configuration to link the credential to the correct holder binding key.
// The proofs are the cryptographic proofs (e.g. JWTs) that the holder can present alongside the credential to prove possession of the private keys.
func (s *holderBindingKeyService) CreateKeyPairsWithProofs(ctx context.Context, num uint, proofBuilder proofs.ProofBuilder) (publicKeyIdentifiers []models.PublicHolderBindingKey, proofs []string, err error) {
	keyTuples, proofs, err := mintProofKeys(ctx, s.provider, num, proofBuilder)
	if err != nil {
		return nil, nil, err
	}

	publicKeyIdentifiers, err = s.storePrivateKeys(keyTuples)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to storage private keys: %v", err)
	}

	return
}

// mintProofKeys mints num holder keys with their proofs: in the wallet
// provider's HSM when the wallet has one, in software otherwise. With a
// provider present, keys are never silently minted in software instead.
//
// The provider is unlocked through the session in ctx, which asks for the PIN
// the first time and activates the wallet unit if it never was.
func mintProofKeys(ctx context.Context, provider walletprovider.WalletProvider, num uint, proofBuilder proofs.ProofBuilder) ([]keyTuple, []string, error) {
	if provider == nil {
		return generateProofKeys(num, proofBuilder)
	}
	external, ok := proofBuilder.(proofs.ExternalProofBuilder)
	if !ok {
		return nil, nil, fmt.Errorf("proof builder %T cannot be signed by a wallet provider", proofBuilder)
	}
	session := walletunit.SessionFrom(ctx)
	if session == nil {
		return nil, nil, walletunit.ErrNoSession
	}
	unlocked, err := session.Unlocked(ctx, walletprovider.Scope{
		Purpose:      walletprovider.PurposeIssuancePoP,
		Counterparty: external.Audience(),
	}, true)
	if err != nil {
		return nil, nil, err
	}
	return generateProviderProofKeys(ctx, unlocked, num, external)
}

// generateProviderProofKeys mints num keys in the wallet provider's HSM and
// signs their proofs in one batch: the signing inputs of all proofs are built
// first, then signed with one call, so a batch costs one round trip to the
// provider rather than one per key.
func generateProviderProofKeys(ctx context.Context, unlocked walletprovider.UnlockedWalletUnit, num uint, external proofs.ExternalProofBuilder) ([]keyTuple, []string, error) {
	holderKeys, err := unlocked.GenerateKeys(ctx, int(num))
	if err != nil {
		return nil, nil, fmt.Errorf("wallet provider failed to generate holder keys: %w", err)
	}
	if len(holderKeys) != int(num) {
		return nil, nil, fmt.Errorf("wallet provider generated %d holder keys, want %d", len(holderKeys), num)
	}

	requests := make([]walletprovider.SignRequest, num)
	for i, key := range holderKeys {
		input, err := external.SigningInput(key.Public)
		if err != nil {
			return nil, nil, err
		}
		requests[i] = walletprovider.SignRequest{Ref: key.Ref, SigningInput: input}
	}
	sigs, err := unlocked.Sign(ctx, requests)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet provider failed to sign proofs: %w", err)
	}
	if len(sigs) != len(requests) {
		return nil, nil, fmt.Errorf("wallet provider made %d signatures, want %d", len(sigs), len(requests))
	}

	keyTuples := make([]keyTuple, num)
	proofStrings := make([]string, num)
	for i, key := range holderKeys {
		jwkPubKey, err := signingJwk(key.Public)
		if err != nil {
			return nil, nil, err
		}
		proofStrings[i] = proofs.AssembleCompactJws(requests[i].SigningInput, sigs[i])
		keyTuples[i] = keyTuple{
			ref:       key.Ref,
			pub:       key.Public,
			jwkPubKey: jwkPubKey,
			didUrl:    extractDidUrlFromProof(&proofStrings[i]),
		}
	}
	return keyTuples, proofStrings, nil
}

// signingJwk returns pub as a JWK marked for signature use.
func signingJwk(pub *ecdsa.PublicKey) (jwk.Key, error) {
	key, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ecdsa pub key to jwk: %v", err)
	}
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("failed to set key usage on jwk pub key: %v", err)
	}
	return key, nil
}

// generateProofKeys mints num fresh P-256 key pairs and builds one OpenID4VCI
// proof of possession per key with the given builder. Shared by every format's
// HolderKeyBinder: the keys and proofs are the same whatever table the private
// half ends up in.
func generateProofKeys(num uint, proofBuilder proofs.ProofBuilder) ([]keyTuple, []string, error) {
	proofStrings := make([]string, num)
	keyTuples := make([]keyTuple, num)

	for i := range num {
		// TODO: base the choice key type on the supported algorithms in the credential configuration (proof_types_supported / proof_signing_alg_values_supported)
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ecdsa private key: %v", err)
		}

		// Create JWK for the key, which we'll use both in storage and in the proof builder
		jwkPrivKey, err := jwk.Import[jwk.Key](privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		jwkPubKey, err := jwkPrivKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to obtain pub key from priv jwk: %v", err)
		}
		err = jwkPubKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set key usage on jwk pub key: %v", err)
		}

		// TODO: rebuild proof builder to take the JWK as input instead of the private key, so we can avoid converting back and forth between JWK and ecdsa.PrivateKey

		proof, err := proofBuilder.Build(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build proof: %v", err)
		}

		keyTuples[i] = keyTuple{
			privKey:   privKey,
			pub:       &privKey.PublicKey,
			jwkPubKey: jwkPubKey,
		}

		// TODO: this currently only supports the proof builder returning a string (which is the case for the JwtProofBuilder), but we need to support other types of proof in the future
		if proofStr, ok := proof.(string); ok {
			proofStrings[i] = proofStr

			// Extract the DID URL (if any)
			keyTuples[i].didUrl = extractDidUrlFromProof(&proofStr)
		} else {
			return nil, nil, fmt.Errorf("proof builder did not return a string")
		}
	}

	return keyTuples, proofStrings, nil
}

func (s *holderBindingKeyService) storePrivateKeys(keys []keyTuple) (publicKeyIdentifiers []models.PublicHolderBindingKey, err error) {
	publicKeyIdentifiers = make([]models.PublicHolderBindingKey, len(keys))

	keyModels := make([]models.HolderBindingKey, len(keys))

	for i, key := range keys {
		privKeyBytes, err := key.privateKeyBytes()
		if err != nil {
			return nil, err
		}

		keyModels[i] = models.HolderBindingKey{
			Algorithm:  models.KeyAlgorithmECDSA,
			KeyBackend: key.backend(),
			PrivateKey: privKeyBytes,
			ECDSA: &models.ECDSAKeyMetadata{
				CurveName: key.pub.Curve.Params().Name,
			},
		}

		// If a DID has been generated as proof, we store the DID instead of the public key thumbprint, to be able to link the key to the proof. If no DID is present, we fall back to storing the thumbprint of the public key.
		if key.didUrl != nil {
			keyModels[i].DidUrl = datatypes.NullString{V: *key.didUrl, Valid: true}
		} else {
			thumbprintBytes, err := key.jwkPubKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
			}
			thumbprint := hex.EncodeToString(thumbprintBytes)
			keyModels[i].PublicKeyThumbprint = datatypes.NullString{V: thumbprint, Valid: true}
			publicKeyIdentifiers[i].PublicKeyThumbprint = &thumbprint
		}
	}

	err = s.store.StoreKeys(keyModels)
	if err != nil {
		return nil, fmt.Errorf("failed to store holder binding keys: %v", err)
	}

	// Make sure we expose only public key material (DID URL or JWK thumbprint) in the returned publicKeyIdentifiers, not the private keys or other metadata
	for i, keyModel := range keyModels {
		publicKeyIdentifiers[i].ID = keyModel.ID
		if keyModels[i].DidUrl.Valid {
			publicKeyIdentifiers[i].DidUrl = &keyModels[i].DidUrl.V
		}
		if keyModels[i].PublicKeyThumbprint.Valid {
			publicKeyIdentifiers[i].PublicKeyThumbprint = &keyModels[i].PublicKeyThumbprint.V
		}
	}

	return
}

func (s *holderBindingKeyService) RemoveAllKeys() error {
	return s.store.DeleteAll()
}

// RemoveKeys deletes the keys with the given ids, telling the wallet provider
// to delete the ones in its HSM. The local rows go regardless: a key the
// provider failed to delete is unreachable from this wallet either way.
func (s *holderBindingKeyService) RemoveKeys(ids []datatypes.UUID) error {
	var refs []string
	for _, id := range ids {
		key, err := s.store.GetByID(id)
		if errors.Is(err, db.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if ref := key.ProviderKeyRef(); ref != "" {
			refs = append(refs, ref)
		}
	}
	providerErr := removeProviderKeys(s.provider, refs)
	for _, id := range ids {
		if err := s.store.DeleteKey(id); err != nil {
			return err
		}
	}
	return providerErr
}

// removeProviderKeys asks the wallet provider to delete the keys with the
// given refs.
func removeProviderKeys(provider walletprovider.WalletProvider, refs []string) error {
	if len(refs) == 0 {
		return nil
	}
	if provider == nil {
		return fmt.Errorf("%d wallet provider keys to remove, but the wallet has no wallet provider", len(refs))
	}
	if err := provider.RemoveKeys(context.Background(), refs); err != nil {
		return fmt.Errorf("wallet provider failed to remove holder keys: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sdjwt.KeyBindingStorage implementation
// ---------------------------------------------------------------------------

var _ sdjwt.KeyBindingStorage = (*holderBindingKeyService)(nil)

// ResolveHolderKey returns the key a credential bound to pubKey is signed
// with: the software key, or the wallet provider's reference to it.
func (s *holderBindingKeyService) ResolveHolderKey(pubKey jwk.Key) (holdersigning.Key, error) {
	storedKey, err := s.findKey(pubKey)
	if err != nil {
		return holdersigning.Key{}, err
	}
	if ref := storedKey.ProviderKeyRef(); ref != "" {
		return holdersigning.External(ref), nil
	}
	priv, err := decodePKCS8PrivateKey(storedKey.PrivateKey)
	if err != nil {
		return holdersigning.Key{}, err
	}
	return holdersigning.Software(priv), nil
}

func (s *holderBindingKeyService) GetAndRemovePrivateKey(pubKey jwk.Key) (*ecdsa.PrivateKey, error) {
	storedKey, err := s.findKey(pubKey)
	if err != nil {
		return nil, err
	}
	if storedKey.KeyBackend == models.KeyBackendWalletProvider {
		return nil, fmt.Errorf("holder binding key %s lives in the wallet provider's HSM", storedKey.ID)
	}
	return decodePKCS8PrivateKey(storedKey.PrivateKey)
}

// findKey looks the stored key up by the kid of pubKey (a DID URL, as a did:jwk
// or did:key cnf resolves to) or else by its JWK thumbprint.
func (s *holderBindingKeyService) findKey(pubKey jwk.Key) (*models.HolderBindingKey, error) {
	// Try lookup by DID URL first (if kid is set, e.g. from did:jwk cnf resolution).
	kid, hasKid := pubKey.KeyID()
	if hasKid && kid != "" {
		storedKey, err := s.store.GetByDidUrl(kid)
		if err == nil {
			return storedKey, nil
		}
		// Strip fragment and try the base DID.
		if baseDid := stripFragment(kid); baseDid != kid {
			storedKey, err = s.store.GetByDidUrl(baseDid)
			if err == nil {
				return storedKey, nil
			}
		}
	}

	// Fall back to thumbprint lookup.
	thumbprintBytes, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %v", err)
	}
	thumbprint := hex.EncodeToString(thumbprintBytes)

	storedKey, err := s.store.GetByThumbprint(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("failed to find holder binding key for thumbprint %s or kid %s: %v", thumbprint, kid, err)
	}
	return storedKey, nil
}

func (s *holderBindingKeyService) StorePrivateKeys(_ []*ecdsa.PrivateKey) error {
	return fmt.Errorf("use CreateKeyPairsWithProofs to store keys via the OID4VCI issuance flow")
}

func (s *holderBindingKeyService) RemovePrivateKeys(_ []jwk.Key) error {
	return nil
}

func (s *holderBindingKeyService) RemoveAllPrivateKeys() error {
	return s.store.DeleteAll()
}

func decodePKCS8PrivateKey(pkcs8Bytes []byte) (*ecdsa.PrivateKey, error) {
	privKeyAny, err := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
	}
	ecdsaKey, ok := privKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored key is not an ECDSA private key")
	}
	return ecdsaKey, nil
}

func stripFragment(didUrl string) string {
	if before, _, ok := strings.Cut(didUrl, "#"); ok {
		return before
	}
	return didUrl
}

// extractDidUrlFromProof extracts the DID URL from the `kid` JWS header of a proof JWT,
// returning nil if the proof is absent or if the `kid` is not a DID URL.
func extractDidUrlFromProof(proof *string) *string {
	if proof == nil {
		return nil
	}

	msg, err := jws.Parse([]byte(*proof))
	if err != nil {
		return nil
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil
	}

	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok || !strings.HasPrefix(kid, "did:") {
		return nil
	}

	return &kid
}
