package eudi_vcdm_dcql

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didkey"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// VcdmDcqlHandler implements dcql.DcqlCredentialQueryHandler for jwt_vc_json
// credentials stored in the EUDI SQLCipher storage.
type VcdmDcqlHandler struct {
	credentialStore  db.CredentialStore
	holderKeyStore   db.HolderBindingKeyStore
	keyBinder        sdjwtvc.KeyBinder
	kbJwtReplayGuard kbJwtReplayGuard
}

type kbJwtReplayGuard interface {
	CheckAndStore(kbjwt string, issuedAt time.Time) error
}

type inMemoryKbJwtReplayGuard struct {
	mu   sync.Mutex
	seen map[string]int64
}

type persistentKbJwtReplayGuard struct {
	store db.KbJwtReplayStore
}

func newInMemoryKbJwtReplayGuard() *inMemoryKbJwtReplayGuard {
	return &inMemoryKbJwtReplayGuard{seen: map[string]int64{}}
}

func (g *inMemoryKbJwtReplayGuard) CheckAndStore(kbjwt string, issuedAt time.Time) error {
	if g == nil {
		return nil
	}

	now := time.Now().Unix()
	minIssuedAt := now - sdjwtvc.ClockSkewInSeconds

	g.mu.Lock()
	defer g.mu.Unlock()

	for digest, seenIssuedAt := range g.seen {
		if seenIssuedAt < minIssuedAt {
			delete(g.seen, digest)
		}
	}

	digestBytes := sha256.Sum256([]byte(kbjwt))
	digest := hex.EncodeToString(digestBytes[:])
	if _, ok := g.seen[digest]; ok {
		return fmt.Errorf("replay detected")
	}

	g.seen[digest] = issuedAt.Unix()
	return nil
}

func newPersistentKbJwtReplayGuard(store db.KbJwtReplayStore) *persistentKbJwtReplayGuard {
	return &persistentKbJwtReplayGuard{store: store}
}

func (g *persistentKbJwtReplayGuard) CheckAndStore(kbjwt string, issuedAt time.Time) error {
	if g == nil || g.store == nil {
		return nil
	}

	now := time.Now().UTC()
	if err := g.store.DeleteExpired(now); err != nil {
		return fmt.Errorf("failed to prune replay store: %w", err)
	}

	digestBytes := sha256.Sum256([]byte(kbjwt))
	digest := hex.EncodeToString(digestBytes[:])

	exists, err := g.store.ExistsDigest(digest)
	if err != nil {
		return fmt.Errorf("failed to query replay store: %w", err)
	}
	if exists {
		return fmt.Errorf("replay detected")
	}

	baseTime := issuedAt.UTC()
	if now.After(baseTime) {
		baseTime = now
	}
	expiresAt := baseTime.Add(time.Duration(sdjwtvc.ClockSkewInSeconds) * time.Second)

	if err := g.store.StoreDigest(digest, expiresAt); err != nil {
		// Handle concurrent writers that pass the ExistsDigest check simultaneously.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return fmt.Errorf("replay detected")
		}
		return fmt.Errorf("failed to persist replay state: %w", err)
	}

	return nil
}

// NewVcdmDcqlHandler creates a new handler backed by the provided EUDI storage.
func NewVcdmDcqlHandler(eudiStorage storage.Storage) *VcdmDcqlHandler {
	holderBindingKeyService := services.NewHolderBindingKeyService(eudiStorage.Db())
	replayStore := db.NewKbJwtReplayStore(eudiStorage.Db())
	return &VcdmDcqlHandler{
		credentialStore:  db.NewCredentialStore(eudiStorage.Db()),
		holderKeyStore:   db.NewHolderBindingKeyStore(eudiStorage.Db()),
		keyBinder:        sdjwtvc.NewDefaultKeyBinder(holderBindingKeyService),
		kbJwtReplayGuard: newPersistentKbJwtReplayGuard(replayStore),
	}
}

// NewVcdmDcqlHandlerWithStore exists for tests that inject a custom store.
func NewVcdmDcqlHandlerWithStore(credentialStore db.CredentialStore) *VcdmDcqlHandler {
	return &VcdmDcqlHandler{
		credentialStore:  credentialStore,
		keyBinder:        sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage()),
		kbJwtReplayGuard: newInMemoryKbJwtReplayGuard(),
	}
}

// NewVcdmDcqlHandlerWithStoreAndKeyBinder exists for tests that inject both
// a custom store and holder-binding key binder.
func NewVcdmDcqlHandlerWithStoreAndKeyBinder(credentialStore db.CredentialStore, keyBinder sdjwtvc.KeyBinder) *VcdmDcqlHandler {
	return &VcdmDcqlHandler{
		credentialStore:  credentialStore,
		keyBinder:        keyBinder,
		kbJwtReplayGuard: newInMemoryKbJwtReplayGuard(),
	}
}

var _ dcql.DcqlCredentialQueryHandler = (*VcdmDcqlHandler)(nil)

func (h *VcdmDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(models.CredentialFormatW3CVC)
}

func (h *VcdmDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	batches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	vctSet := make(map[string]struct{}, len(query.VctValues()))
	for _, vct := range query.VctValues() {
		vctSet[vct] = struct{}{}
	}

	now := time.Now()
	for _, batch := range batches {
		if batch.Format != models.CredentialFormatW3CVC {
			continue
		}
		if len(vctSet) > 0 {
			if _, ok := vctSet[batch.CredentialType]; !ok {
				continue
			}
		}
		if !isBatchValid(batch, now) {
			continue
		}
		if batch.BatchSize > 1 && batch.RemainingCount == 0 {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal(batch.ProcessedClaims, &payload); err != nil {
			continue
		}

		if !matchesQueryClaims(payload, query.Claims) {
			continue
		}

		candidate := &clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.CredentialType,
			Hash:                        batch.Hash,
			Name:                        credentialDisplayName(batch),
			Issuer:                      issuerTrustedParty(batch),
			Format:                      clientmodels.CredentialFormat(batch.Format),
			BatchInstanceCountRemaining: batchInstanceCountRemaining(batch),
			Attributes:                  buildSelectableAttributes(payload, query.Claims),
			ExpiryDate:                  expiryUnix(batch),
			Revoked:                     false,
			RevocationSupported:         false,
		}
		if batch.IssuanceDate.Valid {
			x := batch.IssuanceDate.V.Unix()
			candidate.IssuanceDate = &x
		}

		result.OwnedCandidates = append(result.OwnedCandidates, candidate)
	}

	return result, nil
}

func (h *VcdmDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	_ = nonce
	_ = clientId

	result := &dcql.PreparedDisclosure{}

	for _, sel := range selections {
		batch, err := h.credentialStore.GetBatchByHash(sel.CredentialHash)
		if err != nil {
			return nil, fmt.Errorf("failed to load credential batch for hash %s: %w", sel.CredentialHash, err)
		}
		if batch.Format != models.CredentialFormatW3CVC {
			return nil, fmt.Errorf("credential hash %s is not a jwt_vc_json credential", sel.CredentialHash)
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
		}

		rawCredential := strings.TrimSpace(string(instance.RawCredential))
		if rawCredential == "" {
			return nil, fmt.Errorf("empty jwt_vc_json credential instance for hash %s", sel.CredentialHash)
		}

		presentation := rawCredential

		// jwt_vc_json disclosures are transported in vp_token.
		// When holder binding is required by the verifier, generate a key-binding
		// proof bound to nonce/client_id and verify it locally before disclosure.
		if sel.RequireHolderBinding {
			holderBoundPresentation, err := createHolderBoundJwtVcPresentation(rawCredential, nonce, clientId, h.keyBinder, h.resolveHolderKeyFromJkt)
			if err != nil {
				return nil, fmt.Errorf("holder binding required for credential hash %s: %w", sel.CredentialHash, err)
			}
			if err := verifyHolderBoundJwtVcPresentationWithReplay(holderBoundPresentation, nonce, clientId, h.resolveHolderKeyFromJkt, h.kbJwtReplayGuard); err != nil {
				return nil, fmt.Errorf("holder binding verification failed for credential hash %s: %w", sel.CredentialHash, err)
			}
			presentation = holderBoundPresentation
		}

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{presentation},
		})

		if batch.BatchSize > 1 {
			if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
				return nil, fmt.Errorf("failed to mark instance as used: %w", err)
			}
		}

		result.CredentialLogs = append(result.CredentialLogs, buildLogCredential(batch, sel.ClaimPaths))
	}

	return result, nil
}

func buildLogCredential(batch *models.CredentialBatch, claimPaths [][]any) clientmodels.LogCredential {
	var payload map[string]any
	_ = json.Unmarshal(batch.ProcessedClaims, &payload)

	log := clientmodels.LogCredential{
		CredentialId:        batch.CredentialType,
		Formats:             []clientmodels.CredentialFormat{clientmodels.CredentialFormat(batch.Format)},
		Name:                credentialDisplayName(batch),
		Issuer:              issuerTrustedParty(batch),
		Attributes:          buildLogAttributes(payload, claimPaths),
		ExpiryDate:          expiryUnix(batch),
		Revoked:             false,
		RevocationSupported: false,
	}

	if batch.IssuanceDate.Valid {
		x := batch.IssuanceDate.V.Unix()
		log.IssuanceDate = &x
	}

	return log
}

func buildLogAttributes(payload map[string]any, claimPaths [][]any) []clientmodels.Attribute {
	if len(payload) == 0 {
		return nil
	}

	if len(claimPaths) == 0 {
		keys := make([]string, 0, len(payload))
		for key := range payload {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		attrs := make([]clientmodels.Attribute, 0, len(keys))
		for _, key := range keys {
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath: []any{key},
				Value:     clientmodels.NewAttributeValue(payload[key]),
			})
		}
		return attrs
	}

	seen := map[string]struct{}{}
	attrs := make([]clientmodels.Attribute, 0, len(claimPaths))
	for _, path := range claimPaths {
		if len(path) == 0 {
			continue
		}
		key := clientmodels.ClaimPathKey(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		value, ok := lookupPath(payload, path)
		if !ok {
			continue
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath: append([]any{}, path...),
			Value:     clientmodels.NewAttributeValue(value),
		})
	}
	return attrs
}

func isBatchValid(batch *models.CredentialBatch, now time.Time) bool {
	if batch.NotBefore.Valid && now.Before(batch.NotBefore.V) {
		return false
	}
	if batch.ExpiresAt.Valid && now.After(batch.ExpiresAt.V) {
		return false
	}
	return true
}

func batchInstanceCountRemaining(batch *models.CredentialBatch) *uint {
	if batch.BatchSize <= 1 {
		return nil
	}
	return &batch.RemainingCount
}

func expiryUnix(batch *models.CredentialBatch) *int64 {
	if !batch.ExpiresAt.Valid {
		return nil
	}
	x := batch.ExpiresAt.V.Unix()
	return &x
}

func credentialDisplayName(batch *models.CredentialBatch) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		for _, d := range batch.CredentialMetadata.Display {
			if d.Name == "" {
				continue
			}
			ts := clientmodels.TranslatedString{}
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid && d.Locale.V != "" {
				locale = d.Locale.V
			}
			ts[locale] = d.Name
			return ts
		}
	}
	return clientmodels.TranslatedString{clientmodels.DefaultFallbackLanguage: batch.CredentialType}
}

func issuerTrustedParty(batch *models.CredentialBatch) clientmodels.TrustedParty {
	name := clientmodels.TranslatedString{}
	for _, d := range batch.IssuerDisplay {
		if d.Name == "" {
			continue
		}
		locale := clientmodels.DefaultFallbackLanguage
		if d.Locale.Valid && d.Locale.V != "" {
			locale = d.Locale.V
		}
		name[locale] = d.Name
	}
	if len(name) == 0 {
		name[clientmodels.DefaultFallbackLanguage] = batch.CredentialIssuer
	}

	return clientmodels.TrustedParty{
		Id:       batch.CredentialIssuer,
		Name:     name,
		Verified: false,
	}
}

func matchesQueryClaims(payload map[string]any, claims []dcql.Claim) bool {
	for _, claim := range claims {
		if len(claim.Path) == 0 {
			continue
		}
		value, ok := lookupPath(payload, claim.Path)
		if !ok {
			return false
		}
		if len(claim.Values) == 0 {
			continue
		}
		matched := false
		for _, expected := range claim.Values {
			if valuesEqual(value, expected) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func buildSelectableAttributes(payload map[string]any, claims []dcql.Claim) []clientmodels.Attribute {
	if len(claims) > 0 {
		attrs := make([]clientmodels.Attribute, 0, len(claims))
		for _, claim := range claims {
			if len(claim.Path) == 0 {
				continue
			}
			value, ok := lookupPath(payload, claim.Path)
			if !ok {
				continue
			}
			attr := clientmodels.Attribute{
				ClaimPath: append([]any{}, claim.Path...),
				Value:     clientmodels.NewAttributeValue(value),
			}
			if len(claim.Values) > 0 {
				attr.RequestedValue = clientmodels.NewAttributeValue(claim.Values[0])
			}
			attrs = append(attrs, attr)
		}
		return attrs
	}

	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	attrs := make([]clientmodels.Attribute, 0, len(keys))
	for _, key := range keys {
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath: []any{key},
			Value:     clientmodels.NewAttributeValue(payload[key]),
		})
	}
	return attrs
}

func lookupPath(root any, path []any) (any, bool) {
	current := root
	for _, part := range path {
		switch node := current.(type) {
		case map[string]any:
			key, ok := part.(string)
			if !ok {
				return nil, false
			}
			next, ok := node[key]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			idx, ok := indexOf(part)
			if !ok || idx < 0 || idx >= len(node) {
				return nil, false
			}
			current = node[idx]
		default:
			return nil, false
		}
	}
	return current, true
}

func indexOf(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if float64(int(n)) == n {
			return int(n), true
		}
	}
	return 0, false
}

func valuesEqual(actual any, expected any) bool {
	if af, ok := toFloat64(actual); ok {
		if ef, ok := toFloat64(expected); ok {
			return af == ef
		}
	}
	return reflect.DeepEqual(actual, expected)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func ensureJwtVcHasHolderBinding(rawCredential string) error {
	_, err := extractHolderBindingPublicKeyFromJwtVc(rawCredential, nil)
	return err
}

func createHolderBoundJwtVcPresentation(rawCredential string, nonce string, clientId string, keyBinder sdjwtvc.KeyBinder, jktResolver func(string) (jwk.Key, error)) (string, error) {
	holderKey, err := extractHolderBindingPublicKeyFromJwtVc(rawCredential, jktResolver)
	if err != nil {
		return "", err
	}

	hash, err := sdjwtvc.CreateUrlEncodedHash(iana.SHA256, rawCredential)
	if err != nil {
		return "", fmt.Errorf("failed to hash jwt_vc_json credential: %w", err)
	}

	kbjwt, err := keyBinder.CreateKeyBindingJwt(hash, holderKey, nonce, clientId)
	if err != nil {
		return "", fmt.Errorf("failed to create key binding jwt: %w", err)
	}

	return rawCredential + "~" + string(kbjwt), nil
}

func verifyHolderBoundJwtVcPresentation(presentation string, expectedNonce string, expectedClientID string, jktResolver func(string) (jwk.Key, error)) error {
	return verifyHolderBoundJwtVcPresentationWithReplay(presentation, expectedNonce, expectedClientID, jktResolver, nil)
}

func verifyHolderBoundJwtVcPresentationWithReplay(presentation string, expectedNonce string, expectedClientID string, jktResolver func(string) (jwk.Key, error), replayGuard kbJwtReplayGuard) error {
	credential, kbjwt, ok := strings.Cut(presentation, "~")
	if !ok || strings.TrimSpace(kbjwt) == "" {
		return fmt.Errorf("missing key binding jwt")
	}

	holderKey, err := extractHolderBindingPublicKeyFromJwtVc(credential, jktResolver)
	if err != nil {
		return err
	}

	rawHolderKey, err := publicKeyFromJwk(holderKey)
	if err != nil {
		return fmt.Errorf("failed to export holder key: %w", err)
	}

	token, err := jwt.Parse(kbjwt, func(token *jwt.Token) (any, error) {
		if token.Method == nil {
			return nil, fmt.Errorf("missing signing method")
		}
		return rawHolderKey, nil
	})
	if err != nil {
		return fmt.Errorf("invalid key binding jwt signature: %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("invalid key binding jwt")
	}

	typ, _ := token.Header["typ"].(string)
	if typ != sdjwtvc.KbJwtTyp {
		return fmt.Errorf("invalid key binding jwt typ %q", typ)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid key binding jwt claims")
	}

	nonce, _ := claims["nonce"].(string)
	if nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}

	aud, _ := claims["aud"].(string)
	if aud != expectedClientID {
		return fmt.Errorf("audience mismatch")
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("invalid issued-at claim")
	}
	if issuedAt == nil {
		return fmt.Errorf("missing issued-at claim")
	}
	if issuedAt.Time.Unix() > time.Now().Unix()+sdjwtvc.ClockSkewInSeconds {
		return fmt.Errorf("issued-at is in the future")
	}

	sdHash, _ := claims["sd_hash"].(string)
	expectedHash, err := sdjwtvc.CreateUrlEncodedHash(iana.SHA256, credential)
	if err != nil {
		return fmt.Errorf("failed to hash jwt_vc_json credential: %w", err)
	}
	if sdHash != expectedHash {
		return fmt.Errorf("sd_hash mismatch")
	}

	if replayGuard != nil {
		if err := replayGuard.CheckAndStore(kbjwt, issuedAt.Time); err != nil {
			return err
		}
	}

	return nil
}

func extractHolderBindingPublicKeyFromJwtVc(rawCredential string, jktResolver func(string) (jwk.Key, error)) (jwk.Key, error) {
	payload, err := parseJwtVcPayload(rawCredential)
	if err != nil {
		return nil, err
	}

	cnfRaw, ok := payload["cnf"]
	if !ok {
		return nil, fmt.Errorf("missing cnf claim")
	}

	cnf, ok := cnfRaw.(map[string]any)
	if !ok || len(cnf) == 0 {
		return nil, fmt.Errorf("invalid cnf claim")
	}

	if jwkRaw, ok := cnf["jwk"]; ok {
		jwkJSON, err := json.Marshal(jwkRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid cnf.jwk")
		}
		key, err := jwk.ParseKey(jwkJSON)
		if err != nil {
			return nil, fmt.Errorf("invalid cnf.jwk")
		}
		return key, nil
	}

	if kidRaw, ok := cnf["kid"]; ok {
		kid, ok := kidRaw.(string)
		if !ok || strings.TrimSpace(kid) == "" {
			return nil, fmt.Errorf("invalid cnf.kid")
		}
		if strings.HasPrefix(kid, didjwk.Prefix) || strings.HasPrefix(strings.SplitN(kid, "#", 2)[0], didjwk.Prefix) {
			key, err := didjwk.Resolve(kid)
			if err != nil {
				return nil, fmt.Errorf("invalid cnf.kid")
			}
			_ = key.Set(jwk.KeyIDKey, kid)
			return key, nil
		}
		if strings.HasPrefix(kid, didkey.Prefix) {
			rawPubKey, err := didkey.Resolve(kid)
			if err != nil {
				return nil, fmt.Errorf("invalid cnf.kid")
			}
			key, err := jwk.Import(rawPubKey)
			if err != nil {
				return nil, fmt.Errorf("invalid cnf.kid")
			}
			_ = key.Set(jwk.KeyIDKey, kid)
			return key, nil
		}
		return nil, fmt.Errorf("unsupported cnf.kid DID method")
	}

	if _, ok := cnf["jkt"]; ok {
		jkt, ok := cnf["jkt"].(string)
		if !ok || strings.TrimSpace(jkt) == "" {
			return nil, fmt.Errorf("invalid cnf.jkt")
		}
		if jktResolver == nil {
			return nil, fmt.Errorf("unsupported cnf.jkt for holder binding proof generation")
		}
		key, err := jktResolver(jkt)
		if err != nil {
			return nil, fmt.Errorf("invalid cnf.jkt")
		}
		return key, nil
	}

	return nil, fmt.Errorf("cnf claim does not contain supported key binding fields")
}

func (h *VcdmDcqlHandler) resolveHolderKeyFromJkt(jkt string) (jwk.Key, error) {
	if h == nil || h.holderKeyStore == nil {
		return nil, fmt.Errorf("holder binding key store unavailable")
	}

	thumbprintBytes, err := base64.RawURLEncoding.DecodeString(jkt)
	if err != nil {
		return nil, fmt.Errorf("invalid jkt")
	}

	storedKey, err := h.holderKeyStore.GetByThumbprint(hex.EncodeToString(thumbprintBytes))
	if err != nil {
		return nil, fmt.Errorf("unknown jkt")
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(storedKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key material")
	}

	var publicKeyAny any
	switch privateKey := privateKeyAny.(type) {
	case *ecdsa.PrivateKey:
		publicKeyAny = privateKey.Public()
	case *rsa.PrivateKey:
		publicKeyAny = privateKey.Public()
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	key, err := jwk.Import(publicKeyAny)
	if err != nil {
		return nil, fmt.Errorf("invalid public key")
	}

	computedThumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil || !reflect.DeepEqual(computedThumbprint, thumbprintBytes) {
		return nil, fmt.Errorf("jkt thumbprint mismatch")
	}

	return key, nil
}

func parseJwtVcPayload(rawCredential string) (map[string]any, error) {
	parts := strings.Split(rawCredential, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt_vc_json credential")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt payload encoding")
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid jwt payload json")
	}

	return payload, nil
}

func publicKeyFromJwk(holderKey jwk.Key) (any, error) {
	pubKey, err := holderKey.PublicKey()
	if err != nil {
		return nil, err
	}

	var raw any
	if err := jwk.Export(pubKey, &raw); err != nil {
		return nil, err
	}

	return raw, nil
}
