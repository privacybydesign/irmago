// Package eudi_sdjwt_dcql implements a DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI).
package eudi_sdjwt_dcql

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// isIrmaStyleVct reports whether vct looks like an IRMA scheme credential
// identifier ("scheme.issuer.credential"): exactly three non-empty segments
// separated by dots, none of which contain ':' or '/' (so URN/URL forms are
// excluded even if they happen to have three dot-separated parts).
func isIrmaStyleVct(vct string) bool {
	parts := strings.Split(vct, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, ":/") {
			return false
		}
	}
	return true
}

// isHttpVct reports whether vct is an absolute http(s) URL that the type
// metadata fetcher can safely GET. Used to skip URN / scheme-less vcts
// (e.g. "urn:eudi:pid:1") without invoking http.Get, which would otherwise
// emit a per-disclosure "unsupported protocol scheme" warning.
func isHttpVct(vct string) bool {
	return strings.HasPrefix(vct, "https://") || strings.HasPrefix(vct, "http://")
}

// SdJwtVcDcqlHandler implements dcql.DcqlCredentialQueryHandler for SD-JWT-VC
// credentials stored in the eudi storage (SQLite).
type SdJwtVcDcqlHandler struct {
	storage         storage.Storage
	credentialStore db.CredentialStore
	keyBinder       sdjwtvc.KeyBinder
	vctFetcher      typemetadata.VctFetcher
	issuerFetcher   typemetadata.IssuerFetcher

	// statusChecker, when non-nil, performs a live (cache-aware) Token Status
	// List check while building the disclosure plan, so a candidate's Revoked
	// flag reflects the current status. Nil falls back to the stored
	// LastKnownStatus. The check never blocks disclosure — see FindCandidates.
	statusChecker *statuslist.Checker
}

// NewSdJwtVcDcqlHandler creates a new handler. vctFetcher and issuerFetcher are
// used to describe credentials the wallet has never seen (the verifier requests
// a VCT for which there is no stored batch). Pass nil to disable that path; the
// handler will then return empty obtainable descriptors as before.
//
// keyBinder is the KB-JWT signer used when a presentation requires holder
// binding. Pass sdjwtvc.NewDefaultKeyBinder(services.NewHolderBindingKeyService(
// eudiStorage.Db())) for the default software, storage-backed signer, or a
// WSCA/HSM-backed implementation to keep the holder private key out of process.
func NewSdJwtVcDcqlHandler(
	eudiStorage storage.Storage,
	credentialStore db.CredentialStore,
	vctFetcher typemetadata.VctFetcher,
	issuerFetcher typemetadata.IssuerFetcher,
	keyBinder sdjwtvc.KeyBinder,
) *SdJwtVcDcqlHandler {
	return &SdJwtVcDcqlHandler{
		storage:         eudiStorage,
		credentialStore: credentialStore,
		keyBinder:       keyBinder,
		vctFetcher:      vctFetcher,
		issuerFetcher:   issuerFetcher,
	}
}

// WithStatusChecker installs a Token Status List checker used to determine the
// Revoked flag on disclosure candidates via a live (cache-aware) check. When
// unset, the handler falls back to the stored LastKnownStatus.
func (h *SdJwtVcDcqlHandler) WithStatusChecker(c *statuslist.Checker) *SdJwtVcDcqlHandler {
	h.statusChecker = c
	return h
}

var _ dcql.DcqlCredentialQueryHandler = (*SdJwtVcDcqlHandler)(nil)

// CanHandleCredentialQuery returns true for any sd-jwt query whose vct_values
// are not 3-component IRMA scheme identifiers (those are handled by
// irma_sdjwt_dcql against the BBolt store). URL and URN vcts — and any other
// non-IRMA-shaped identifier — route here. Queries without vct_values are
// also handled here so the EUDI store still gets searched.
//
// The discrimination is purely structural — there is no semantic check that
// the URL/URN is reachable, that the URN sits in any recognised namespace,
// or that the EUDI store actually holds the requested type. See
// isIrmaStyleVct for the boundary conditions of the shape check.
func (h *SdJwtVcDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	if query.Format != "dc+sd-jwt" && query.Format != "vc+sd-jwt" {
		return false
	}
	if len(query.VctValues()) == 0 {
		return true
	}
	for _, vct := range query.VctValues() {
		if !isIrmaStyleVct(vct) {
			return true
		}
	}
	return false
}

func (h *SdJwtVcDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	batches, err := h.findBatches(query)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	hasExhaustedBatch := false
	for _, batch := range batches {
		if !isBatchValid(batch, now) {
			continue
		}
		// Skip exhausted batches: when a batch was issued with multiple instances
		// and all have been used, the credential is no longer disclosable.
		if batch.BatchSize > 1 && batch.RemainingCount == 0 {
			hasExhaustedBatch = true
			continue
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			continue
		}
		rawSdJwt := sdjwtvc.SdJwtVc(instance.RawCredential)
		attributes, err := parseBatchAttributes(batch, query, rawSdJwt)
		if err != nil {
			continue
		}
		if attributes == nil {
			continue
		}

		image := h.credentialImage(batch)

		candidate := clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.VerifiableCredentialType,
			Hash:                        batch.Hash,
			Name:                        credentialDisplayName(batch),
			Issuer:                      h.issuerTrustedParty(batch),
			Format:                      clientmodels.Format_SdJwtVc,
			BatchInstanceCountRemaining: batchInstanceCountRemaining(batch),
			Attributes:                  attributes,
			ExpiryDate:                  expiryUnix(batch),
			Image:                       image,
			Revoked:                     h.liveRevoked(instance, batch.IssuerURL),
			RevocationSupported:         instance.StatusListURI != nil,
		}

		if batch.IssuedAt.Valid {
			x := batch.IssuedAt.V.Unix()
			candidate.IssuanceDate = &x
		}

		result.OwnedCandidates = append(result.OwnedCandidates, &candidate)
	}

	// If matching batches exist but all are exhausted and no usable candidates
	// remain, return an error so the session fails instead of showing an empty
	// disclosure plan.
	if hasExhaustedBatch && len(result.OwnedCandidates) == 0 {
		return nil, fmt.Errorf("all credential instances for the requested type are exhausted")
	}

	// When no usable owned candidates were emitted -- either the wallet has
	// no batches at all OR every batch was filtered out by claim matching --
	// emit one descriptor with an empty IssueURL so the user sees what is
	// being requested instead of a stuck permission prompt. See the
	// "missing credentials" plan.
	if len(result.OwnedCandidates) == 0 && len(query.VctValues()) > 0 && h.vctFetcher != nil {
		if descriptor := h.composeUnobtainableDescriptor(query); descriptor != nil {
			result.ObtainableDescriptors = append(result.ObtainableDescriptors, descriptor)
		}
	}

	return result, nil
}

// liveRevoked reports whether the instance's credential is currently revoked.
// It performs a live (cache-aware) Token Status List check on the instance so
// the disclosure plan reflects the current status rather than the last
// background sweep. When no checker is configured it falls back to the stored
// status; when a checker is configured but the check fails (the cached token is
// past its own ttl and the re-fetch failed) it fails safe to revoked. Either
// way it never blocks disclosure: revocation is surfaced as a flag for the
// frontend, with the verifier as the backstop.
func (h *SdJwtVcDcqlHandler) liveRevoked(instance *models.IssuedCredentialInstance, issuer string) bool {
	if instance.StatusListURI == nil || instance.StatusListIdx == nil {
		return false
	}
	if h.statusChecker == nil {
		// No checker configured (status checking disabled): best-effort from the
		// last stored status.
		return statuslist.Status(instance.LastKnownStatus) == statuslist.StatusInvalid
	}
	ref := statuslist.Reference{URI: *instance.StatusListURI, Index: *instance.StatusListIdx}
	// context.Background: the disclosure planning path carries no cancellable
	// context. Both network steps are still bounded — the status-list GET by the
	// checker's FetchTimeout and did:web signing-key resolution by the
	// timeout-bounded HTTP client used for DID resolution (didweb.NewHTTPClient)
	// — so this call cannot hang indefinitely.
	status, err := h.statusChecker.Check(context.Background(), ref, issuer)
	if err != nil {
		// Check is cache-aware: it serves the cached status list token while it is
		// within its OWN ttl (draft-ietf-oauth-status-list §8.2) and re-fetches
		// once expired. An error therefore means no status is available within its
		// validity window (the cached token is past its ttl and the re-fetch
		// failed), so we cannot vouch for the credential — fail safe.
		eudi.Logger.Warnf("statuslist: no in-ttl status for instance %s (live check failed), treating as revoked: %v", instance.ID, err)
		return true
	}
	// Revoked means definitively INVALID — matching GetCredentialMetadataList
	// and the no-checker branch above. Suspended / application-specific statuses
	// are not surfaced as revoked here.
	return status == statuslist.StatusInvalid
}

// composeUnobtainableDescriptor builds a CredentialDescriptor for a credential
// the wallet has never seen, by fetching the SD-JWT VC Type Metadata document
// (and, if the type metadata exposes an issuer URL, the issuer's well-known
// document). The returned descriptor's IssueURL is always nil — that is the
// wire-level signal to the frontend that the session cannot be completed.
//
// Walks query.VctValues in order; first VCT whose type-metadata fetch succeeds
// wins. If every VCT fetch fails, returns a URL-only descriptor for the first
// VCT (so the user still sees what was requested).
func (h *SdJwtVcDcqlHandler) composeUnobtainableDescriptor(query dcql.CredentialQuery) *clientmodels.CredentialDescriptor {
	vctValues := query.VctValues()
	if len(vctValues) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, vct := range vctValues {
		// The fetcher delegates to http.Get, which fails with "unsupported
		// protocol scheme" for URN / non-http vct values and would emit a
		// noisy warning on every disclosure attempt. Skip those quietly —
		// the URL-only fallback below still emits a descriptor so the user
		// sees what was requested.
		if !isHttpVct(vct) {
			continue
		}
		vctMeta, err := h.vctFetcher.Fetch(ctx, vct)
		if err != nil {
			eudi.Logger.Warnf("failed to fetch VCT type metadata from %q: %v", vct, err)
			continue
		}
		return buildUnobtainableDescriptor(vct, vctMeta, h.fetchIssuerMetadata(ctx, vctMeta.IssuerURL), query)
	}

	// All VCT fetches failed: emit a URL-only descriptor for the first VCT so
	// the user still sees what was asked for.
	return buildUnobtainableDescriptor(vctValues[0], nil, nil, query)
}

func (h *SdJwtVcDcqlHandler) fetchIssuerMetadata(ctx context.Context, issuerURL string) *typemetadata.IssuerMetadata {
	if issuerURL == "" || h.issuerFetcher == nil {
		return nil
	}
	im, err := h.issuerFetcher.Fetch(ctx, issuerURL)
	if err != nil {
		eudi.Logger.Warnf("failed to fetch issuer metadata from %q: %v", issuerURL, err)
		// Issuer fetch failure is tolerated — we still know the issuer URL.
		return &typemetadata.IssuerMetadata{Id: issuerURL}
	}
	return im
}

// buildUnobtainableDescriptor assembles the final CredentialDescriptor from
// (optionally absent) VCT and issuer metadata. CredentialId is the VCT URL.
// IssueURL is always nil. Attributes are derived from the DCQL claim paths,
// with display names from the type-metadata when available.
func buildUnobtainableDescriptor(
	vctURL string,
	vctMeta *typemetadata.VctTypeMetadata,
	issuerMeta *typemetadata.IssuerMetadata,
	query dcql.CredentialQuery,
) *clientmodels.CredentialDescriptor {
	desc := &clientmodels.CredentialDescriptor{
		CredentialId: vctURL,
		Name:         vctName(vctMeta),
		Issuer:       issuerTrustedParty(issuerMeta),
		Attributes:   queryAttributes(query, vctMeta),
	}
	return desc
}

// vctName extracts a TranslatedString credential name from the VCT type
// metadata's display entries (or the top-level name as fallback). Returns an
// empty TranslatedString when no name is available.
func vctName(vctMeta *typemetadata.VctTypeMetadata) clientmodels.TranslatedString {
	name := clientmodels.TranslatedString{}
	if vctMeta == nil {
		return name
	}
	for _, d := range vctMeta.Display {
		if d.Name == "" {
			continue
		}
		locale := d.Locale
		if locale == "" {
			locale = clientmodels.DefaultFallbackLanguage
		}
		name[locale] = d.Name
	}
	if len(name) == 0 && vctMeta.Name != "" {
		name[clientmodels.DefaultFallbackLanguage] = vctMeta.Name
	}
	return name
}

// issuerTrustedParty builds a TrustedParty from issuer metadata. Empty fields
// when the metadata is nil. Logo is intentionally not fetched (the unobtainable
// path stays inside the user's permission-prompt budget); frontend can resolve
// the logo URL itself if it wants.
func issuerTrustedParty(issuerMeta *typemetadata.IssuerMetadata) clientmodels.TrustedParty {
	if issuerMeta == nil {
		return clientmodels.TrustedParty{}
	}
	return clientmodels.TrustedParty{
		Id:   issuerMeta.Id,
		Name: issuerMeta.Name,
	}
}

// queryAttributes maps each top-level DCQL claim path to a placeholder
// Attribute (no Value), enriched with a display name from the VCT type
// metadata when one is available. Used so the user sees which claims the
// verifier was asking for, even though no credential is held.
func queryAttributes(query dcql.CredentialQuery, vctMeta *typemetadata.VctTypeMetadata) []clientmodels.Attribute {
	if len(query.Claims) == 0 {
		return nil
	}
	attrs := make([]clientmodels.Attribute, 0, len(query.Claims))
	for _, claim := range query.Claims {
		if len(claim.Path) == 0 {
			continue
		}
		display := claimDisplayFromVct(vctMeta, claim.Path)
		var dn *clientmodels.TranslatedString
		if len(display) > 0 {
			dn = &display
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   append([]any{}, claim.Path...),
			DisplayName: dn,
		})
	}
	return attrs
}

// claimDisplayFromVct returns the localized display name for a claim path from
// the VCT type metadata, or an empty TranslatedString when none is available.
func claimDisplayFromVct(vctMeta *typemetadata.VctTypeMetadata, path []any) clientmodels.TranslatedString {
	if vctMeta == nil {
		return nil
	}
	for _, c := range vctMeta.Claims {
		if !claimPathMatchesMetadataPath(path, c.Path) {
			continue
		}
		ts := clientmodels.TranslatedString{}
		for _, d := range c.Display {
			if d.Name == "" {
				continue
			}
			locale := d.Locale
			if locale == "" {
				locale = clientmodels.DefaultFallbackLanguage
			}
			ts[locale] = d.Name
		}
		if len(ts) > 0 {
			return ts
		}
	}
	return nil
}

// findBatches returns credential batches matching the query, with metadata
// preloaded (including claim display names). Only batches whose VCT matches
// one of the requested vct_values are returned. When no vct_values are
// specified, no batches are returned.
func (h *SdJwtVcDcqlHandler) findBatches(query dcql.CredentialQuery) ([]*models.CredentialBatch, error) {
	vctValues := query.VctValues()
	if len(vctValues) == 0 {
		return nil, nil
	}

	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, err
	}

	vctSet := make(map[string]struct{}, len(vctValues))
	for _, vct := range vctValues {
		vctSet[vct] = struct{}{}
	}
	var filtered []*models.CredentialBatch
	for _, batch := range allBatches {
		if _, ok := vctSet[batch.VerifiableCredentialType]; ok {
			filtered = append(filtered, batch)
		}
	}
	return filtered, nil
}

func (h *SdJwtVcDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	result := &dcql.PreparedDisclosure{}

	// Load all batches with full metadata so buildLogCredential can resolve display names.
	allBatches, err := h.credentialStore.GetCredentialBatchList()
	if err != nil {
		return nil, fmt.Errorf("failed to load credential batches: %w", err)
	}
	batchByHash := make(map[string]*models.CredentialBatch, len(allBatches))
	for _, b := range allBatches {
		batchByHash[b.Hash] = b
	}

	for _, sel := range selections {
		batch, ok := batchByHash[sel.CredentialHash]
		if !ok {
			return nil, fmt.Errorf("batch not found for hash %s", sel.CredentialHash)
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
		}

		rawSdJwt := sdjwtvc.SdJwtVc(instance.RawCredential)

		selected, err := sdjwtvc.CreatePresentation(rawSdJwt, sel.ClaimPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create presentation: %w", err)
		}

		presentation := string(selected)
		if sel.RequireHolderBinding {
			kbjwt, err := sdjwtvc.CreateKbJwt(selected, h.keyBinder, nonce, clientId)
			if err != nil {
				return nil, fmt.Errorf("failed to create kbjwt: %w", err)
			}
			presentation = string(sdjwtvc.AddKeyBindingJwtToSdJwtVc(selected, kbjwt))
		}

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{presentation},
		})

		// Only mark the instance as used when the original batch had multiple instances.
		// A batch of 1 keeps its single instance reusable.
		if batch.BatchSize > 1 {
			if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
				return nil, fmt.Errorf("failed to mark instance as used: %w", err)
			}
		}

		result.CredentialLogs = append(result.CredentialLogs, h.buildLogCredential(batch, sel.ClaimPaths))
	}

	return result, nil
}

// parseBatchAttributes builds the disclosure-plan attribute list for a batch
// by previewing what the verifier would actually receive if the user grants
// permission for the DCQL-requested claims. SD-JWT disclosures are atomic: a
// disclosure's value is whatever the issuer signed into it, so a request for
// a single deep leaf may pull in sibling fields the issuer bundled into the
// same disclosure. The plan must show those bundled fields up front,
// otherwise the user would consent to a release that's wider than what they
// see in the UI.
//
// Returns nil if the credential doesn't satisfy the query's value
// constraints. When claim_sets is present, each set is tried in order and the
// first fully satisfiable set determines which claims are included.
func parseBatchAttributes(batch *models.CredentialBatch, query dcql.CredentialQuery, rawSdJwt sdjwtvc.SdJwtVc) ([]clientmodels.Attribute, error) {
	var resolved sdjwtvc.ProcessedSdJwtPayload
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &resolved); err != nil {
		return nil, err
	}

	claims := selectClaims(query, &resolved)
	if claims == nil {
		return nil, nil
	}

	// OpenID4VP Section 6.3: wallets should ignore duplicate claim queries.
	// Dedup by the full serialized path. Track which expanded paths carry a
	// value constraint so we can stamp RequestedValue on their leaf attributes.
	requestedPaths, constrainedKeys := expandClaimsToConcretePaths(claims, &resolved)

	// Compute the verifier-side view of the SD-JWT for these paths. Hidden
	// _sd entries are stripped, hidden array-element digests stay nil, and any
	// extra fields bundled into the same disclosure value as a requested
	// path appear inline — exactly what the verifier ends up with.
	//
	// When the raw SD-JWT isn't available (or doesn't parse), fall back to
	// flattening the resolved payload at the requested paths. That keeps the
	// pre-existing behavior for unit tests that work with synthetic batches,
	// at the cost of not previewing bundled siblings in those tests.
	leafPaths := computeDisclosurePreviewLeaves(rawSdJwt, requestedPaths, &resolved, batch.VerifiableCredentialType)
	pairs := buildPairsFromLeaves(leafPaths, constrainedKeys)

	metadataOrder := buildMetadataOrder(batch)
	attributes := make([]clientmodels.Attribute, 0)
	requestedKeys := make(map[string]struct{})
	attributes = flattenPathsForDisplay(attributes, requestedKeys, batch, &resolved, pairs, metadataOrder)

	return attributes, nil
}

// computeDisclosurePreviewLeaves returns the leaf paths that should appear in
// the disclosure plan. Production path: simulate the verifier-side view from
// the raw SD-JWT and walk every visible leaf, so the user sees any sibling
// fields bundled into the same disclosure as a requested leaf. Fallback path
// (raw SD-JWT empty or unparseable, e.g. in unit tests with synthetic
// batches): walk the resolved payload at each requested path. The fallback
// loses the bundled-sibling preview but preserves the old behavior when the
// SD-JWT structure isn't accessible.
func computeDisclosurePreviewLeaves(
	rawSdJwt sdjwtvc.SdJwtVc,
	requestedPaths [][]any,
	resolved *sdjwtvc.ProcessedSdJwtPayload,
	credentialType string,
) [][]any {
	if len(rawSdJwt) > 0 {
		view, err := sdjwtvc.PostDisclosureView(rawSdJwt, requestedPaths)
		if err == nil {
			return collectViewLeafPaths(view)
		}
		eudi.Logger.Warnf(
			"failed to compute post-disclosure view for %q (falling back to requested-path flattening): %v",
			credentialType, err,
		)
	}
	return collectResolvedLeavesAtPaths(resolved, requestedPaths)
}

// collectResolvedLeavesAtPaths walks the resolved payload at each requested
// path. Scalar values become single leaves; compound values are walked
// recursively. Used as the fallback when the verifier-side view isn't
// available — it reproduces the pre-refactor behavior for unit tests that
// don't carry a parseable raw SD-JWT.
func collectResolvedLeavesAtPaths(resolved *sdjwtvc.ProcessedSdJwtPayload, paths [][]any) [][]any {
	var leaves [][]any
	seen := make(map[string]struct{})
	for _, p := range paths {
		val, err := resolved.GetClaimValue(p)
		if err != nil {
			continue
		}
		walkLeafPaths(val, append([]any{}, p...), func(leaf []any) {
			key := clientmodels.ClaimPathKey(leaf)
			if _, dup := seen[key]; dup {
				return
			}
			seen[key] = struct{}{}
			leaves = append(leaves, leaf)
		})
	}
	return leaves
}

// expandClaimsToConcretePaths walks each DCQL claim, expands null wildcards
// into concrete array indices using the resolved payload, and then expands
// any compound endpoint into all its descendant leaf paths. The latter step
// matters because an SD-JWT presentation needs every nested disclosure
// included — a request for ["university"] alone would only release the
// university SD entry, which (when the issuer made each sub-field its own
// SD) is empty to the verifier. Walking to leaves means each per-leaf SD
// disclosure also gets selected by collectSelectedDisclosures.
//
// Returns the concrete leaf paths and the set of paths (by ClaimPathKey)
// that carry a value constraint. The constrained set includes both the
// original DCQL path and any leaves expanded under it, so RequestedValue
// stamping works for value-constrained scalars.
func expandClaimsToConcretePaths(claims []dcql.Claim, payload *sdjwtvc.ProcessedSdJwtPayload) ([][]any, map[string]struct{}) {
	seenPaths := make(map[string]struct{})
	constrained := make(map[string]struct{})
	var paths [][]any
	for _, claim := range claims {
		key := clientmodels.ClaimPathKey(claim.Path)
		if _, dup := seenPaths[key]; dup {
			continue
		}
		seenPaths[key] = struct{}{}
		hasConstraint := len(claim.Values) > 0
		for _, cp := range expandNullPaths(claim.Path, payload) {
			leaves := descendantLeafPaths(payload, cp)
			for _, leaf := range leaves {
				paths = append(paths, leaf)
				if hasConstraint {
					constrained[clientmodels.ClaimPathKey(leaf)] = struct{}{}
				}
			}
		}
	}
	return paths, constrained
}

// descendantLeafPaths returns every scalar leaf path reachable from `path` in
// the resolved payload. If the value at `path` is itself a scalar, returns
// [path]. If it's a compound (object/array), recurses to the leaves.
func descendantLeafPaths(payload *sdjwtvc.ProcessedSdJwtPayload, path []any) [][]any {
	val, err := payload.GetClaimValue(path)
	if err != nil {
		// Path doesn't resolve in the resolved payload — fall back to the
		// path itself so the caller can still attempt to walk it.
		return [][]any{path}
	}
	var leaves [][]any
	walkLeafPaths(val, append([]any{}, path...), func(p []any) {
		leaves = append(leaves, p)
	})
	if len(leaves) == 0 {
		// e.g., path resolves to an empty object/array — return the path
		// itself so the caller still emits something for it.
		return [][]any{path}
	}
	return leaves
}

// collectViewLeafPaths walks a verifier-side view and returns the path of
// every visible scalar leaf. Standard JWT/SD-JWT meta keys at the top level
// (iss, iat, exp, vct, cnf, …) are skipped entirely — including their
// subtrees — because they are not user data. Nil placeholders (representing
// hidden array-element digests) are skipped.
func collectViewLeafPaths(view map[string]any) [][]any {
	var leaves [][]any
	for k, child := range view {
		if _, std := sdjwtvc.StandardClaims[k]; std {
			continue
		}
		walkLeafPaths(child, []any{k}, func(path []any) {
			leaves = append(leaves, path)
		})
	}
	return leaves
}

// walkLeafPaths visits every scalar leaf in value, calling visit with the
// full path. nil values represent verifier-hidden positions and are skipped.
func walkLeafPaths(value any, prefix []any, visit func([]any)) {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			next := append(append([]any{}, prefix...), k)
			walkLeafPaths(child, next, visit)
		}
	case []any:
		for i, child := range v {
			next := append(append([]any{}, prefix...), i)
			walkLeafPaths(child, next, visit)
		}
	default:
		if v == nil || len(prefix) == 0 {
			return
		}
		visit(append([]any{}, prefix...))
	}
}

// buildPairsFromLeaves turns concrete leaf paths into pathToFlatten entries,
// stamping hasConstraint when the leaf path had a DCQL value constraint.
// Duplicate paths are dropped.
func buildPairsFromLeaves(leafPaths [][]any, constrainedKeys map[string]struct{}) []pathToFlatten {
	seen := make(map[string]struct{}, len(leafPaths))
	pairs := make([]pathToFlatten, 0, len(leafPaths))
	for _, p := range leafPaths {
		key := clientmodels.ClaimPathKey(p)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		_, hasConstraint := constrainedKeys[key]
		pairs = append(pairs, pathToFlatten{
			path:          p,
			hasConstraint: hasConstraint,
		})
	}
	return pairs
}

// loadRawSdJwt fetches the raw issuer-signed SD-JWT bytes for a batch via the
// credential store. Used by parseBatchAttributes to compute the post-disclosure
// view and by other helpers that need to inspect the JWT structure.
func loadRawSdJwt(batch *models.CredentialBatch, credStore db.CredentialStore) (sdjwtvc.SdJwtVc, error) {
	instance, err := credStore.GetUnusedInstance(batch.ID)
	if err != nil {
		return "", fmt.Errorf("failed to load credential instance for batch %s: %w", batch.ID, err)
	}
	return sdjwtvc.SdJwtVc(instance.RawCredential), nil
}

// pathToFlatten describes one concrete claim path that should be emitted into
// the disclosure-plan / log attribute list, along with its rendering context.
type pathToFlatten struct {
	path []any
	// hasConstraint marks this path's leaf attributes for RequestedValue
	// (used by the UI when the verifier specified a value constraint).
	hasConstraint bool
}

// flattenPathsForDisplay emits attributes for a list of concrete claim paths,
// in tree-walk order. Each path produces (1) any compound-named ancestor
// headers not yet emitted, deduped by concrete path key; (2) the path's
// flattened value via flattenForDisclosure. Compound non-SD values without a
// metadata display name get a synthetic header from fallbackDisplay so they
// still render as a section in the UI. RequestedValue is stamped on leaf
// attributes added during a path's processing when hasConstraint is set.
func flattenPathsForDisplay(
	attrs []clientmodels.Attribute,
	requestedKeys map[string]struct{},
	batch *models.CredentialBatch,
	payload *sdjwtvc.ProcessedSdJwtPayload,
	pairs []pathToFlatten,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	sort.SliceStable(pairs, func(i, j int) bool {
		return pathLess(pairs[i].path, pairs[j].path, metadataOrder)
	})

	for _, p := range pairs {
		prevLen := len(attrs)

		// Emit headers for compound-named ancestors. Dedup keys are concrete
		// so each array-element subtree carries its own block.
		for i := 1; i < len(p.path); i++ {
			ancestor := p.path[:i]
			if isArrayIndex(ancestor[len(ancestor)-1]) {
				continue
			}
			key := clientmodels.ClaimPathKey(ancestor)
			if _, seen := requestedKeys[key]; seen {
				continue
			}
			requestedKeys[key] = struct{}{}
			d := claimDisplayName(batch, ancestor)
			if len(d) == 0 {
				continue
			}
			dn := d
			attrs = append(attrs, clientmodels.Attribute{
				ClaimPath:   append([]any{}, ancestor...),
				DisplayName: &dn,
			})
		}

		val, _ := payload.GetClaimValue(p.path)
		attrs = flattenForDisclosure(attrs, requestedKeys, batch, p.path, val, metadataOrder)

		if p.hasConstraint {
			for i := prevLen; i < len(attrs); i++ {
				if attrs[i].Value != nil {
					attrs[i].RequestedValue = attrs[i].Value
				}
			}
		}
	}
	return attrs
}

// selectClaims determines which claims to use for matching. When claim_sets is
// present, it tries each set in order and returns the claims from the first
// fully satisfiable set. Without claim_sets, all claims must match.
// Returns nil if the credential doesn't satisfy the query.
func selectClaims(query dcql.CredentialQuery, payload *sdjwtvc.ProcessedSdJwtPayload) []dcql.Claim {
	// OpenID4VP Section 6.4.1: if claims is absent, the verifier requests no
	// selectively disclosable claims. Return empty (non-nil) to indicate the
	// credential matches but no SD claims are requested.
	if len(query.Claims) == 0 {
		return []dcql.Claim{}
	}

	if len(query.ClaimSets) == 0 {
		// No claim_sets: all claims must match.
		for _, claim := range query.Claims {
			if !claimMatches(claim, payload) {
				return nil
			}
		}
		return query.Claims
	}

	// Build lookup from claim ID to claim.
	claimById := make(map[string]dcql.Claim, len(query.Claims))
	for _, claim := range query.Claims {
		if claim.Id != "" {
			claimById[claim.Id] = claim
		}
	}

	// Try each claim set in order; return the first where every claim matches.
	for _, set := range query.ClaimSets {
		var matched []dcql.Claim
		allFound := true
		for _, id := range set {
			claim, ok := claimById[id]
			if !ok || !claimMatches(claim, payload) {
				allFound = false
				break
			}
			matched = append(matched, claim)
		}
		if allFound {
			return matched
		}
	}

	return nil
}

// claimMatches checks whether a single claim exists in the payload and satisfies
// any value constraints. Supports string, boolean, and numeric comparisons as
// required by the DCQL spec (OpenID4VP Section 6.3).
// Null path components (wildcards) are expanded: the claim matches if ANY array
// element satisfies the remaining path.
func claimMatches(claim dcql.Claim, payload *sdjwtvc.ProcessedSdJwtPayload) bool {
	return claimMatchesPath(claim.Path, claim.Values, payload)
}

// claimMatchesPath recursively resolves a claim path against the payload,
// expanding null wildcards into concrete array indices.
func claimMatchesPath(path []any, values []any, payload *sdjwtvc.ProcessedSdJwtPayload) bool {
	// Find the first null in the path.
	nullIdx := -1
	for i, c := range path {
		if c == nil {
			nullIdx = i
			break
		}
	}

	if nullIdx == -1 {
		// No nulls — resolve directly.
		val, err := payload.GetClaimValue(path)
		if err != nil {
			return false
		}
		if len(values) > 0 {
			for _, reqVal := range values {
				if claimValuesEqual(val, reqVal) {
					return true
				}
			}
			return false
		}
		return true
	}

	// Resolve the prefix up to the null to get the array.
	prefix := path[:nullIdx]
	arr, err := payload.GetClaimValue(prefix)
	if err != nil {
		return false
	}
	slice, ok := arr.([]any)
	if !ok {
		return false
	}

	// Check if ANY element matches the remaining path after the null.
	suffix := path[nullIdx+1:]
	for i := range slice {
		concretePath := make([]any, 0, len(prefix)+1+len(suffix))
		concretePath = append(concretePath, prefix...)
		concretePath = append(concretePath, i)
		concretePath = append(concretePath, suffix...)
		if claimMatchesPath(concretePath, values, payload) {
			return true
		}
	}
	return false
}

// claimValuesEqual compares two values from JSON-decoded data. JSON numbers are
// float64, so we normalize both sides to float64 for numeric comparison.
func claimValuesEqual(actual, expected any) bool {
	// Direct equality covers strings and booleans.
	if actual == expected {
		return true
	}
	// JSON numbers are float64; the constraint value may also be float64.
	// Normalize both to float64 for comparison.
	af, aOk := toFloat64(actual)
	ef, eOk := toFloat64(expected)
	return aOk && eOk && af == ef
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func (h *SdJwtVcDcqlHandler) buildLogCredential(batch *models.CredentialBatch, claimPaths [][]any) clientmodels.LogCredential {
	attrs := make([]clientmodels.Attribute, 0)

	var resolved sdjwtvc.ProcessedSdJwtPayload
	if err := json.Unmarshal([]byte(batch.ProcessedSdJwtPayload), &resolved); err != nil {
		eudi.Logger.Warnf("failed to unmarshal processed SD-JWT payload for %q: %v", batch.VerifiableCredentialType, err)
	}

	// Compute the verifier-side view for the user's authorized paths so the
	// log records exactly what was transmitted, including any sibling
	// fields the issuer bundled into the same disclosure value as a
	// requested leaf.
	rawSdJwt, err := loadRawSdJwt(batch, h.credentialStore)
	if err != nil {
		eudi.Logger.Warnf("failed to load raw SD-JWT for log credential %q: %v", batch.VerifiableCredentialType, err)
	}
	view, err := sdjwtvc.PostDisclosureView(rawSdJwt, claimPaths)
	if err != nil {
		eudi.Logger.Warnf("failed to compute post-disclosure view for log credential %q: %v", batch.VerifiableCredentialType, err)
	}

	leafPaths := collectViewLeafPaths(view)
	pairs := buildPairsFromLeaves(leafPaths, nil)

	metadataOrder := buildMetadataOrder(batch)
	requestedKeys := make(map[string]struct{})
	attrs = flattenPathsForDisplay(attrs, requestedKeys, batch, &resolved, pairs, metadataOrder)

	log := clientmodels.LogCredential{
		CredentialId: batch.VerifiableCredentialType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
		Name:         credentialDisplayName(batch),
		Image:        h.credentialImage(batch),
		Issuer:       h.issuerTrustedParty(batch),
		Attributes:   attrs,
		ExpiryDate:   expiryUnix(batch),
	}

	if batch.IssuedAt.Valid {
		x := batch.IssuedAt.V.Unix()
		log.IssuanceDate = &x
	}

	return log
}

func expiryUnix(batch *models.CredentialBatch) *int64 {
	if batch.ExpiresAt.Valid {
		x := batch.ExpiresAt.V.Unix()
		return &x
	}
	return nil
}

// isBatchValid returns false if the credential batch is expired or not yet valid.
// Unix epoch (time.Unix(0,0)) is treated as "not set" because the storage layer
// currently always marks ExpiresAt/NotBefore as Valid, even when the JWT has no
// exp/nbf claims — storing 0 as the timestamp.
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

// flattenForDisclosure recursively flattens arrays and objects into scalar
// attributes, emitting a section header (Value == nil) before each compound
// value that has a display name in the credential metadata. Compound paths are
// added to requestedKeys so the non-SD claim loop does not re-add them.
// Display names come strictly from claimDisplayName; absence means DisplayName: nil.
// Object keys are sorted by their position in the credential metadata, falling
// back to alphabetical for keys not in the metadata.
func flattenForDisclosure(
	attrs []clientmodels.Attribute,
	requestedKeys map[string]struct{},
	batch *models.CredentialBatch,
	path []any,
	value any,
	metadataOrder map[string]int,
) []clientmodels.Attribute {
	switch v := value.(type) {
	case []any:
		pk := clientmodels.ClaimPathKey(path)
		if _, seen := requestedKeys[pk]; !seen {
			requestedKeys[pk] = struct{}{}
			if d := claimDisplayName(batch, path); len(d) > 0 {
				dn := d
				attrs = append(attrs, clientmodels.Attribute{
					ClaimPath:   path,
					DisplayName: &dn,
				})
			}
		}
		for i, elem := range v {
			elemPath := append(append([]any{}, path...), i)
			attrs = flattenForDisclosure(attrs, requestedKeys, batch, elemPath, elem, metadataOrder)
		}
	case map[string]any:
		pk := clientmodels.ClaimPathKey(path)
		if _, seen := requestedKeys[pk]; !seen {
			requestedKeys[pk] = struct{}{}
			if d := claimDisplayName(batch, path); len(d) > 0 {
				dn := d
				attrs = append(attrs, clientmodels.Attribute{
					ClaimPath:   path,
					DisplayName: &dn,
				})
			}
		}
		keys := sortObjectKeysByMetadata(v, path, metadataOrder)
		for _, key := range keys {
			elemPath := append(append([]any{}, path...), key)
			attrs = flattenForDisclosure(attrs, requestedKeys, batch, elemPath, v[key], metadataOrder)
		}
	default:
		pk := clientmodels.ClaimPathKey(path)
		requestedKeys[pk] = struct{}{}
		var dn *clientmodels.TranslatedString
		if d := claimDisplayName(batch, path); len(d) > 0 {
			dnCopy := d
			dn = &dnCopy
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   path,
			DisplayName: dn,
			Value:       clientmodels.NewAttributeValue(value),
		})
	}
	return attrs
}

// sortObjectKeysByMetadata returns the keys of an object sorted by their position
// in the credential metadata. Keys not in the metadata are appended alphabetically.
func sortObjectKeysByMetadata(obj map[string]any, parentPath []any, metadataOrder map[string]int) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi := metadataOrderForKey(parentPath, keys[i], metadataOrder)
		pj := metadataOrderForKey(parentPath, keys[j], metadataOrder)
		if pi != pj {
			return pi < pj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// expandNullPaths expands a claim path with null wildcards into all concrete
// paths by replacing each null with every valid array index. Paths without nulls
// are returned as-is. A trailing null is stripped (the caller will expand the array).
func expandNullPaths(path []any, payload *sdjwtvc.ProcessedSdJwtPayload) [][]any {
	// Strip trailing null — the caller handles array expansion via flattenForDisclosure.
	if len(path) > 0 && path[len(path)-1] == nil {
		path = path[:len(path)-1]
	}

	// Find the first null.
	nullIdx := -1
	for i, c := range path {
		if c == nil {
			nullIdx = i
			break
		}
	}

	if nullIdx == -1 {
		return [][]any{path}
	}

	// Resolve prefix to get the array.
	prefix := path[:nullIdx]
	arr, err := payload.GetClaimValue(prefix)
	if err != nil {
		return nil
	}
	slice, ok := arr.([]any)
	if !ok {
		return nil
	}

	suffix := path[nullIdx+1:]
	var result [][]any
	for i := range slice {
		concrete := make([]any, 0, len(prefix)+1+len(suffix))
		concrete = append(concrete, prefix...)
		concrete = append(concrete, i)
		concrete = append(concrete, suffix...)
		// Recursively expand any remaining nulls.
		result = append(result, expandNullPaths(concrete, payload)...)
	}
	return result
}

// metadataOrderForKey returns the metadata order index for a child key under parentPath.
// Tries both exact and wildcard (null) path matching. Returns maxInt if not found.
func metadataOrderForKey(parentPath []any, key string, metadataOrder map[string]int) int {
	childPath := append(append([]any{}, parentPath...), key)
	if idx, ok := metadataOrder[clientmodels.ClaimPathKey(childPath)]; ok {
		return idx
	}
	wildcard := make([]any, len(childPath))
	hasIndex := false
	for i, c := range childPath {
		if isArrayIndex(c) {
			wildcard[i] = nil
			hasIndex = true
		} else {
			wildcard[i] = c
		}
	}
	if hasIndex {
		if idx, ok := metadataOrder[clientmodels.ClaimPathKey(wildcard)]; ok {
			return idx
		}
	}
	return 1<<31 - 1
}

// buildMetadataOrder creates a map from serialized claim path to position index
// for ordering object keys by their metadata position.
func buildMetadataOrder(batch *models.CredentialBatch) map[string]int {
	order := make(map[string]int)
	if batch.CredentialMetadata == nil {
		return order
	}
	for i, claim := range batch.CredentialMetadata.Claims {
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		order[clientmodels.ClaimPathKey(path)] = i
	}
	return order
}

// isArrayIndex returns true if the path component is a numeric array index.
func isArrayIndex(component any) bool {
	switch component.(type) {
	case int, float64:
		return true
	}
	return false
}

// arrayIndexValue returns the integer value of an array-index path component.
func arrayIndexValue(component any) int {
	switch v := component.(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// pathLess compares two concrete claim paths in tree-walk order: at each level
// array indices are compared numerically; string keys are compared by their
// metadata declaration index (with alphabetical fallback). A shorter path
// orders before a longer one when they share the full common prefix. This
// makes parseBatchAttributes emit attributes in the same order as a
// depth-first walk of the credential value tree, matching FlattenClaimValue.
func pathLess(a, b []any, metadataOrder map[string]int) bool {
	n := min(len(b), len(a))
	for k := range n {
		aIsIdx := isArrayIndex(a[k])
		bIsIdx := isArrayIndex(b[k])
		switch {
		case aIsIdx && bIsIdx:
			ai := arrayIndexValue(a[k])
			bi := arrayIndexValue(b[k])
			if ai != bi {
				return ai < bi
			}
		case !aIsIdx && !bIsIdx:
			ak, _ := a[k].(string)
			bk, _ := b[k].(string)
			if ak == bk {
				continue
			}
			parent := a[:k]
			ai := metadataOrderForKey(parent, ak, metadataOrder)
			bi := metadataOrderForKey(parent, bk, metadataOrder)
			if ai != bi {
				return ai < bi
			}
			return ak < bk
		default:
			// Mixed types at the same level shouldn't occur for valid paths
			// against a single credential. Order strings before indices for
			// determinism.
			return !aIsIdx
		}
	}
	return len(a) < len(b)
}

// batchInstanceCountRemaining returns nil for batch-of-1 credentials (infinitely
// reusable) and a pointer to the remaining count for larger batches.
func batchInstanceCountRemaining(batch *models.CredentialBatch) *uint {
	if batch.BatchSize <= 1 {
		return nil
	}
	return &batch.RemainingCount
}

// credentialImage resolves the credential logo from the batch's display metadata.
// Returns nil if no logo is configured or the logo cannot be loaded.
func (h *SdJwtVcDcqlHandler) credentialImage(batch *models.CredentialBatch) *clientmodels.Image {
	if batch.CredentialMetadata == nil {
		return nil
	}
	logoManager := h.storage.FileSystem().Credentials().LogoManager()
	for _, display := range batch.CredentialMetadata.Display {
		if display.LogoURI == "" {
			continue
		}
		if img := eudi.LoadLogoImage(logoManager, display.LogoURI); img != nil {
			return img
		}
	}
	return nil
}

// issuerTrustedParty builds a TrustedParty from the stored issuer display metadata,
// including the issuer logo if available on disk.
func (h *SdJwtVcDcqlHandler) issuerTrustedParty(batch *models.CredentialBatch) clientmodels.TrustedParty {
	name := clientmodels.TranslatedString{}
	for _, d := range batch.IssuerDisplay {
		locale := clientmodels.DefaultFallbackLanguage
		if d.Locale.Valid {
			if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
				locale = base
			}
		}
		name[locale] = d.Name
	}
	return clientmodels.TrustedParty{
		Id:    batch.CredentialIssuer,
		Name:  name,
		Image: h.issuerImage(batch),
	}
}

// issuerImage resolves the issuer logo from the batch's issuer display metadata.
// Returns nil if no logo is configured or the logo cannot be loaded.
func (h *SdJwtVcDcqlHandler) issuerImage(batch *models.CredentialBatch) *clientmodels.Image {
	logoManager := h.storage.FileSystem().Issuers().LogoManager()
	for _, d := range batch.IssuerDisplay {
		if !d.LogoURI.Valid || d.LogoURI.V == "" {
			continue
		}
		if img := eudi.LoadLogoImage(logoManager, d.LogoURI.V); img != nil {
			return img
		}
	}
	return nil
}

// credentialDisplayName returns the display name for a credential from its stored metadata.
// Falls back to the VCT if no display metadata is available.
func credentialDisplayName(batch *models.CredentialBatch) clientmodels.TranslatedString {
	if batch.CredentialMetadata != nil {
		ts := clientmodels.TranslatedString{}
		for _, d := range batch.CredentialMetadata.Display {
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
					locale = base
				}
			}
			ts[locale] = d.Name
		}
		if len(ts) > 0 {
			return ts
		}
	}
	return clientmodels.TranslatedString{clientmodels.DefaultFallbackLanguage: batch.VerifiableCredentialType}
}

// claimDisplayName looks up the display name for a claim from the stored credential
// metadata. Returns an empty TranslatedString when no metadata display entry exists
// for the path — callers treat that as "no display name".
func claimDisplayName(batch *models.CredentialBatch, claimPath []any) clientmodels.TranslatedString {
	if batch.CredentialMetadata == nil {
		return clientmodels.TranslatedString{}
	}
	for _, claim := range batch.CredentialMetadata.Claims {
		if len(claim.Display) == 0 {
			continue
		}
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		if !claimPathMatchesMetadataPath(claimPath, path) {
			continue
		}
		ts := clientmodels.TranslatedString{}
		for _, d := range claim.Display {
			locale := clientmodels.DefaultFallbackLanguage
			if d.Locale.Valid {
				if base, ok := metadata.TryGetBaseLanguageFromLocale(d.Locale.V); ok {
					locale = base
				}
			}
			ts[locale] = d.Name
		}
		if len(ts) > 0 {
			return ts
		}
	}
	return clientmodels.TranslatedString{}
}

// claimPathMatchesMetadataPath checks if a concrete claim path matches a metadata
// path that may contain null wildcards. Null in the metadata path matches any
// integer index in the claim path.
func claimPathMatchesMetadataPath(claimPath []any, metadataPath []any) bool {
	if len(claimPath) != len(metadataPath) {
		return false
	}
	for i := range claimPath {
		if metadataPath[i] == nil {
			// Null wildcard matches any integer index.
			if !isArrayIndex(claimPath[i]) {
				return false
			}
		} else {
			if fmt.Sprintf("%v", claimPath[i]) != fmt.Sprintf("%v", metadataPath[i]) {
				return false
			}
		}
	}
	return true
}
