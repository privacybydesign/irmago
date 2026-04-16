package eudi_mdoc_dcql

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
)

// MdocDcqlHandler implements dcql.DcqlCredentialQueryHandler for ISO 18013-5
// mdoc credentials stored in the eudi SQLite storage.
type MdocDcqlHandler struct {
	credentialStore storage.CredentialStore
}

// NewMdocDcqlHandler returns a handler backed by the supplied storage.
func NewMdocDcqlHandler(s storage.Storage) *MdocDcqlHandler {
	return &MdocDcqlHandler{credentialStore: storage.NewCredentialStore(s)}
}

var _ dcql.DcqlCredentialQueryHandler = (*MdocDcqlHandler)(nil)

// CanHandleCredentialQuery returns true when the query has Format="mso_mdoc"
// and a non-empty doctype_value. Queries without a doctype are rejected
// because mdoc matching is fundamentally doctype-scoped.
func (h *MdocDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	if query.Format != string(clientmodels.Format_Mdoc) {
		return false
	}
	if query.Meta == nil || query.Meta.DocTypeValue == "" {
		return false
	}
	return true
}

// FindCandidates returns all stored mdoc batches whose docType matches the
// query and whose validity window covers "now".
func (h *MdocDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for _, batch := range allBatches {
		if batch.Format != models.CredentialFormatMdoc {
			continue
		}
		if batch.VerifiableCredentialType != query.Meta.DocTypeValue {
			continue
		}
		if !isBatchValid(batch, now) {
			continue
		}
		attrs, err := projectionAttributes(batch, query)
		if err != nil || attrs == nil {
			continue
		}
		result.OwnedCandidates = append(result.OwnedCandidates, &clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.VerifiableCredentialType,
			Hash:                        batch.Hash,
			Name:                        clientmodels.TranslatedString{"en": batch.VerifiableCredentialType},
			Format:                      clientmodels.Format_Mdoc,
			BatchInstanceCountRemaining: &batch.RemainingCount,
			Attributes:                  attrs,
			IssuanceDate:                batch.IssuedAt.Unix(),
			ExpiryDate:                  expiryUnix(batch),
		})
	}
	return result, nil
}

// PrepareDisclosure builds the mdoc DeviceResponse for each selection,
// signing DeviceAuth with the instance's stored device key.
func (h *MdocDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, ctx dcql.DisclosureContext) (*dcql.PreparedDisclosure, error) {
	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, fmt.Errorf("load batches: %w", err)
	}
	byHash := make(map[string]*models.CredentialBatch, len(allBatches))
	for _, b := range allBatches {
		byHash[b.Hash] = b
	}

	sessionTranscript, err := mdoc.BuildOID4VPSessionTranscript(ctx.ClientId, ctx.ResponseUri, ctx.Nonce)
	if err != nil {
		return nil, fmt.Errorf("build SessionTranscript: %w", err)
	}

	result := &dcql.PreparedDisclosure{}
	for _, sel := range selections {
		batch, ok := byHash[sel.CredentialHash]
		if !ok {
			return nil, fmt.Errorf("batch not found for hash %s", sel.CredentialHash)
		}
		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("get unused instance: %w", err)
		}

		issuerSigned, err := mdoc.ParseIssuerSigned(instance.RawCredential)
		if err != nil {
			return nil, fmt.Errorf("parse stored IssuerSigned: %w", err)
		}

		requested, err := groupClaimPathsByNamespace(sel.ClaimPaths)
		if err != nil {
			return nil, err
		}
		filtered, err := mdoc.SelectFromIssuerSigned(issuerSigned, requested)
		if err != nil {
			return nil, fmt.Errorf("selective disclosure: %w", err)
		}

		deviceKey, err := loadInstanceDeviceKey(instance)
		if err != nil {
			return nil, fmt.Errorf("load device key: %w", err)
		}
		deviceSigned, err := mdoc.SignDeviceAuth(sessionTranscript, batch.VerifiableCredentialType, deviceKey)
		if err != nil {
			return nil, fmt.Errorf("sign DeviceAuth: %w", err)
		}

		deviceResponse, err := mdoc.BuildDeviceResponse(
			[]mdoc.Document{{
				DocType:      batch.VerifiableCredentialType,
				IssuerSigned: filtered,
				DeviceSigned: deviceSigned,
			}},
			mdoc.DeviceResponseStatusOK,
		)
		if err != nil {
			return nil, fmt.Errorf("build DeviceResponse: %w", err)
		}

		// Per OpenID4VP §6.4.2, the mdoc vp_token value is the base64url
		// encoding of the DeviceResponse CBOR bytes.
		vpToken := base64.RawURLEncoding.EncodeToString(deviceResponse)

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{vpToken},
		})
		result.CredentialLogs = append(result.CredentialLogs, buildLogCredential(batch, sel.ClaimPaths))

		if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
			return nil, fmt.Errorf("mark used: %w", err)
		}
	}

	return result, nil
}

// ---- helpers ---------------------------------------------------------------

// isBatchValid mirrors the SD-JWT handler: ignore epoch-zero sentinels and
// check nbf/exp against `now`.
func isBatchValid(batch *models.CredentialBatch, now time.Time) bool {
	epoch := time.Unix(0, 0)
	if batch.ExpiresAt.Valid && !batch.ExpiresAt.V.Equal(epoch) && now.After(batch.ExpiresAt.V) {
		return false
	}
	if batch.NotBefore.Valid && !batch.NotBefore.V.Equal(epoch) && now.Before(batch.NotBefore.V) {
		return false
	}
	return true
}

func expiryUnix(batch *models.CredentialBatch) int64 {
	if batch.ExpiresAt.Valid {
		return batch.ExpiresAt.V.Unix()
	}
	return 0
}

// groupClaimPathsByNamespace turns the OpenID4VP claim paths
// (per §6.4.2: `[namespace, elementIdentifier]` for mdoc) into the shape
// SelectFromIssuerSigned accepts.
func groupClaimPathsByNamespace(paths [][]any) (map[string][]string, error) {
	out := make(map[string][]string)
	for i, p := range paths {
		if len(p) != 2 {
			return nil, fmt.Errorf("mdoc claim path %d has %d components, want 2 [namespace, element]", i, len(p))
		}
		ns, ok := p[0].(string)
		if !ok {
			return nil, fmt.Errorf("mdoc claim path %d namespace is %T, want string", i, p[0])
		}
		el, ok := p[1].(string)
		if !ok {
			return nil, fmt.Errorf("mdoc claim path %d element is %T, want string", i, p[1])
		}
		out[ns] = append(out[ns], el)
	}
	return out, nil
}

// projectionAttributes matches the query's claim constraints against the
// stored attribute projection and returns a list of UI attributes. Returns
// nil (without error) when the credential fails the query's value filters.
func projectionAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery) ([]clientmodels.Attribute, error) {
	var projection map[string]map[string]any
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &projection); err != nil {
		return nil, err
	}

	// No claims means the verifier wants everything or doesn't care about
	// specific attributes; return all the attributes we have to offer.
	if len(query.Claims) == 0 {
		return allAttributes(projection), nil
	}

	var attrs []clientmodels.Attribute
	for _, claim := range query.Claims {
		if len(claim.Path) != 2 {
			return nil, fmt.Errorf("mdoc claim path must have 2 components, got %d", len(claim.Path))
		}
		ns, okNS := claim.Path[0].(string)
		el, okEL := claim.Path[1].(string)
		if !okNS || !okEL {
			return nil, fmt.Errorf("mdoc claim path components must be strings")
		}
		nsMap, ok := projection[ns]
		if !ok {
			return nil, nil // namespace absent — credential doesn't match
		}
		val, ok := nsMap[el]
		if !ok {
			return nil, nil // element absent
		}
		if len(claim.Values) > 0 && !anyEquals(claim.Values, val) {
			return nil, nil // value constraint not satisfied
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   []any{ns, el},
			DisplayName: clientmodels.TranslatedString{"en": el},
			Value:       clientmodels.NewAttributeValue(val),
		})
	}
	return attrs, nil
}

func allAttributes(projection map[string]map[string]any) []clientmodels.Attribute {
	var attrs []clientmodels.Attribute
	for ns, inner := range projection {
		for el, val := range inner {
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   []any{ns, el},
				DisplayName: clientmodels.TranslatedString{"en": el},
				Value:       clientmodels.NewAttributeValue(val),
			})
		}
	}
	return attrs
}

func anyEquals(allowed []any, v any) bool {
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}

func buildLogCredential(batch *models.CredentialBatch, claimPaths [][]any) clientmodels.LogCredential {
	var projection map[string]map[string]any
	_ = json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &projection)

	var attrs []clientmodels.Attribute
	for _, path := range claimPaths {
		if len(path) != 2 {
			continue
		}
		ns, okNS := path[0].(string)
		el, okEL := path[1].(string)
		if !okNS || !okEL {
			continue
		}
		val, _ := projection[ns][el]
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   []any{ns, el},
			DisplayName: clientmodels.TranslatedString{"en": el},
			Value:       clientmodels.NewAttributeValue(val),
		})
	}

	return clientmodels.LogCredential{
		CredentialId: batch.VerifiableCredentialType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_Mdoc},
		Name:         clientmodels.TranslatedString{"en": batch.VerifiableCredentialType},
		Attributes:   attrs,
		IssuanceDate: batch.IssuedAt.Unix(),
		ExpiryDate:   expiryUnix(batch),
	}
}

// loadInstanceDeviceKey parses the PKCS#8-encoded ECDSA private key stored
// on the IssuedCredentialInstance's HolderBindingKey row.
func loadInstanceDeviceKey(instance *models.IssuedCredentialInstance) (*ecdsa.PrivateKey, error) {
	if instance.HolderBindingKey == nil {
		return nil, fmt.Errorf("instance has no HolderBindingKey")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(instance.HolderBindingKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	return priv, nil
}
