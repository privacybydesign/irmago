// Package mdoc_dcql implements a DcqlCredentialQueryHandler for mso_mdoc
// credentials stored in the eudi SQLite storage (issued via OpenID4VCI),
// mirroring eudi_sdjwt_dcql for the mdoc format.
package mdoc_dcql

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// DeviceKeyBinder resolves the device key an mdoc presentation must be signed
// with, given the device public key the credential's own MSO is bound to -- the
// same key the verifier will check the resulting signature against.
//
// It exists so the device private key does not have to reach this package, and
// need not exist in this process at all. The wallet's default implementation
// (services.NewMdocDeviceKeyBinder) reads the stored PKCS#8 key, which is
// software all the way down; an implementation backed by a WSCA/HSM or by
// StrongBox / TrustZone / the Secure Enclave returns a mdoc.Holder built on a
// platform key handle instead (mdoc.NewHolderFromSigner), and nothing here
// changes. This mirrors sdjwt.KeyBinder, which eudi_sdjwt_dcql is handed for the
// same reason -- and which is why that handler never touches key material either.
type DeviceKeyBinder interface {
	HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (stdmdoc.Holder, error)
}

// MdocDcqlHandler implements dcql.DcqlCredentialQueryHandler for mso_mdoc
// credentials stored in the eudi storage (SQLite).
type MdocDcqlHandler struct {
	storage         storage.Storage
	credentialStore db.CredentialStore
	deviceKeys      DeviceKeyBinder
	currentLocale   *clientmodels.CurrentLocale
}

// NewMdocDcqlHandler creates a new handler.
//
// deviceKeys signs the DeviceAuthentication of every presentation this handler
// prepares. Pass services.NewMdocDeviceKeyBinder(db.NewHolderBindingKeyStore(
// eudiStorage.Db())) for the default software, storage-backed signer, or a
// hardware-backed implementation to keep the device private key out of process.
func NewMdocDcqlHandler(
	eudiStorage storage.Storage,
	currentLocale *clientmodels.CurrentLocale,
	deviceKeys DeviceKeyBinder,
) *MdocDcqlHandler {
	return &MdocDcqlHandler{
		storage:         eudiStorage,
		credentialStore: db.NewCredentialStore(eudiStorage.Db()),
		deviceKeys:      deviceKeys,
		currentLocale:   currentLocale,
	}
}

var _ dcql.DcqlCredentialQueryHandler = (*MdocDcqlHandler)(nil)

// CanHandleCredentialQuery returns true for any query requesting the
// "mso_mdoc" format -- this package's only responsibility is that one
// format, unlike eudi_sdjwt_dcql/irma_sdjwt_dcql which split SD-JWT-VC
// between two stores by vct shape.
func (h *MdocDcqlHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(clientmodels.Format_MsoMdoc)
}

func (h *MdocDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	result := &dcql.CredentialQueryResult{}

	docType := ""
	if query.Meta != nil {
		docType = query.Meta.DocTypeValue
	}
	if docType == "" {
		return nil, fmt.Errorf("mso_mdoc credential query %q has no doctype_value", query.Id)
	}

	// An absent claims member is refused for mso_mdoc, where eudi_sdjwt_dcql
	// treats it as "no selectively disclosable claims requested" and still
	// matches the credential.
	//
	// That reading is sound for SD-JWT VC, which has an always-disclosed payload
	// left to present. mso_mdoc has none: every element lives in
	// IssuerSigned.NameSpaces and is selectively disclosed, so carrying the same
	// reading here builds a device-signed DeviceResponse over an empty namespaces
	// map -- a valid issuer and device signature over no elements at all, offered
	// to the user beforehand as a credential with an empty attribute list. Both
	// halves are silent: nothing errors, and the verifier receives a well-formed
	// response it can only reject.
	//
	// Refusing matches the Multipaz reference, which treats claims as mandatory
	// when parsing a DCQL query (DcqlQuery.kt reads c["claims"]!!). Neither
	// implementation reads an absent claims member as "disclose everything", so
	// the choice here is between refusing and disclosing nothing.
	if len(query.Claims) == 0 {
		return nil, fmt.Errorf(
			"mso_mdoc credential query %q requests no claims; an mdoc presentation has no always-disclosed payload, so it must name the elements to disclose",
			query.Id)
	}

	// Every claim path is checked before any matching, so a malformed query is
	// reported as malformed. Left to matching, it comes back as "no candidates",
	// which the verifier cannot tell apart from a wallet that simply does not
	// hold the credential -- the one answer that makes a query bug look like a
	// user's empty wallet.
	for _, claim := range query.Claims {
		if _, _, err := mdocPathParts(claim.Path); err != nil {
			return nil, fmt.Errorf("mso_mdoc credential query %q: %w", query.Id, err)
		}
	}

	batches, err := h.credentialStore.GetBatchesByDocType(docType)
	if err != nil {
		return nil, err
	}

	locale := h.currentLocale.Get()
	now := time.Now()
	hasExhaustedBatch := false
	for _, batch := range batches {
		if !dcql.IsBatchValid(batch, now) {
			continue
		}
		if batch.BatchSize > 1 && batch.RemainingCount == 0 {
			hasExhaustedBatch = true
			continue
		}

		resolved, err := unmarshalResolvedClaims(batch)
		if err != nil {
			continue
		}

		claims := selectClaims(query, resolved)
		if claims == nil {
			continue
		}

		candidate := clientmodels.SelectableCredentialInstance{
			CredentialId:                batch.VerifiableCredentialType,
			Hash:                        batch.Hash,
			Name:                        credentialDisplayName(batch, locale),
			Issuer:                      h.issuerTrustedParty(batch, locale),
			Format:                      clientmodels.Format_MsoMdoc,
			DisplayIsFallback:           services.CredentialDisplayIsFallback(batch, locale),
			BatchInstanceCountRemaining: dcql.BatchInstanceCountRemaining(batch),
			Attributes:                  buildAttributes(batch, claims, resolved, locale),
			ExpiryDate:                  dcql.BatchExpiryUnix(batch),
			Image:                       h.credentialImage(batch, locale),
		}
		if batch.IssuedAt.Valid {
			x := batch.IssuedAt.V.Unix()
			candidate.IssuanceDate = &x
		}

		result.OwnedCandidates = append(result.OwnedCandidates, &candidate)
	}

	if hasExhaustedBatch && len(result.OwnedCandidates) == 0 {
		return nil, fmt.Errorf("all credential instances for doctype %q are exhausted", docType)
	}

	// When nothing is owned, emit a URL-less descriptor from the query itself so the
	// user sees what's being requested. Unlike eudi_sdjwt_dcql there's no standardized
	// online discovery document for an mdoc doctype to enrich this with, so it's built
	// purely from the DCQL query's own claim paths.
	if len(result.OwnedCandidates) == 0 {
		result.ObtainableDescriptors = append(result.ObtainableDescriptors, unobtainableDescriptor(docType, query))
	}

	return result, nil
}

// PrepareDisclosure builds a device-signed presentation per selection. The audience is the
// value the presentation is bound to, which for a URL-invoked session is the verifier's
// client identifier -- the value the OpenID4VP session transcript signs over.
func (h *MdocDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, audience string) (*dcql.PreparedDisclosure, error) {
	result := &dcql.PreparedDisclosure{}

	for _, sel := range selections {
		batch, err := h.credentialStore.GetBatchByHash(sel.CredentialHash)
		if err != nil {
			return nil, fmt.Errorf("batch not found for hash %s: %w", sel.CredentialHash, err)
		}

		instance, err := h.credentialStore.GetUnusedInstance(batch.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
		}

		var doc stdmdoc.MDoc
		if err := stdmdoc.Unmarshal(instance.RawCredential, &doc); err != nil {
			return nil, fmt.Errorf("decode stored mdoc: %w", err)
		}

		disclosed, err := selectiveDiscloseByPaths(&doc, sel.ClaimPaths)
		if err != nil {
			return nil, fmt.Errorf("selective disclosure: %w", err)
		}

		// Which key must sign is asked of the credential, not of the key record
		// joined to it: the MSO's deviceKeyInfo is what the issuer bound this
		// credential to and what the verifier checks the device signature
		// against, so a signer resolved from it is the only one that can produce
		// a presentation that verifies. The private half stays behind the binder,
		// which is what allows it to live in hardware -- see DeviceKeyBinder.
		deviceKey, err := stdmdoc.DeviceKeyFromIssuerAuth(doc.IssuerSigned.IssuerAuth)
		if err != nil {
			return nil, fmt.Errorf("read device key of stored mdoc instance %s: %w", instance.ID, err)
		}

		holder, err := h.deviceKeys.HolderForDeviceKey(deviceKey)
		if err != nil {
			return nil, fmt.Errorf("no device key available to sign for credential instance %s: %w", instance.ID, err)
		}

		// Which handover deviceAuth signs is decided by the transport the request
		// arrived on, never by inspecting the values: the DC API's origin-prefixed
		// audience and empty response_uri are indistinguishable here from an
		// ordinary unencrypted URL session, and picking the wrong variant produces
		// a response that transmits and decrypts fine and fails only at the
		// verifier's signature check, with nothing naming the cause.
		transcript, err := h.sessionTranscript(sel, nonce, audience)
		if err != nil {
			return nil, fmt.Errorf("build session transcript: %w", err)
		}

		deviceAuthBytes, err := holder.SignDeviceAuth(batch.VerifiableCredentialType, transcript)
		if err != nil {
			return nil, fmt.Errorf("sign device auth: %w", err)
		}

		presented, err := stdmdoc.AttachDeviceSigned(disclosed, deviceAuthBytes)
		if err != nil {
			return nil, fmt.Errorf("attach device signed: %w", err)
		}

		deviceResponse := stdmdoc.NewDeviceResponse(*presented)
		encoded, err := cbor.Marshal(deviceResponse)
		if err != nil {
			return nil, fmt.Errorf("marshal device response: %w", err)
		}

		result.QueryResponses = append(result.QueryResponses, dcql.QueryResponse{
			QueryId:     sel.QueryId,
			Credentials: []string{base64.RawURLEncoding.EncodeToString(encoded)},
		})

		// Everything that can fail for this selection happens before the instance is
		// burned. Decoding the cached claims for the log entry is fallible, and doing
		// it afterwards meant a failure here consumed a single-use instance on a
		// disclosure that then returned an error and never reached the verifier —
		// the credential silently loses a use. eudi_sdjwt_dcql has nothing fallible
		// after its own MarkInstanceUsed for the same reason.
		resolved, err := unmarshalResolvedClaims(batch)
		if err != nil {
			return nil, fmt.Errorf("decode resolved claims for log: %w", err)
		}

		// Only mark the instance as used when the original batch had multiple instances.
		// A batch of 1 keeps its single instance reusable, mirroring eudi_sdjwt_dcql.
		if batch.BatchSize > 1 {
			if err := h.credentialStore.MarkInstanceUsed(instance.ID); err != nil {
				return nil, fmt.Errorf("failed to mark instance as used: %w", err)
			}
		}

		result.CredentialLogs = append(result.CredentialLogs, h.buildLogCredential(batch, sel.ClaimPaths, resolved))
	}

	return result, nil
}

// sessionTranscript picks the handover variant the transport requires and
// builds the SessionTranscript deviceAuth signs over.
//
// The DC API binds the response to the origin the platform authenticated rather
// than to a client identifier, so the audience arrives origin-prefixed and is
// not what the handover signs; sel.Origin carries the bare value. An empty one
// means the transport was reported without the origin that authenticates it,
// which cannot produce a verifiable signature, so it fails here rather than
// silently signing over "".
func (h *MdocDcqlHandler) sessionTranscript(sel dcql.DisclosureSelection, nonce, audience string) (stdmdoc.SessionTranscript, error) {
	if !sel.OverDcApi {
		return newOpenID4VPSessionTranscript(audience, nonce, sel.ResponseUri, sel.ResponseEncryptionKeyThumbprint)
	}
	if sel.Origin == "" {
		return stdmdoc.SessionTranscript{}, fmt.Errorf(
			"a digital credentials api session must carry the origin the platform authenticated")
	}
	return newDcApiSessionTranscript(sel.Origin, nonce, sel.ResponseEncryptionKeyThumbprint)
}

// ---------------------------------------------------------------------------
// Claim matching
// ---------------------------------------------------------------------------

// unmarshalResolvedClaims decodes a batch's cached namespace -> elementIdentifier
// -> value map.
func unmarshalResolvedClaims(batch *models.CredentialBatch) (map[string]map[string]any, error) {
	var resolved map[string]map[string]any
	if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

// mdocPathParts splits a DCQL claim path into its mandatory [namespace,
// elementIdentifier] components. mso_mdoc claim paths are always exactly two
// string components deep -- ISO 18013-5 has no nested claims, unlike SD-JWT.
func mdocPathParts(path []any) (namespace, elementIdentifier string, err error) {
	if len(path) != 2 {
		return "", "", fmt.Errorf(
			"mso_mdoc claim path must be exactly [namespace, elementIdentifier], got %d component(s): %v",
			len(path), path)
	}
	ns, ok := path[0].(string)
	if !ok {
		return "", "", fmt.Errorf("mso_mdoc claim path namespace must be a string, got %T: %v", path[0], path)
	}
	el, ok := path[1].(string)
	if !ok {
		return "", "", fmt.Errorf("mso_mdoc claim path element identifier must be a string, got %T: %v", path[1], path)
	}
	return ns, el, nil
}

// selectClaims determines which claims to use for matching, mirroring
// eudi_sdjwt_dcql.selectClaims. When claim_sets is present, tries each set in
// order and returns the claims from the first fully satisfiable set. Without
// claim_sets, all claims must match. Returns nil if the credential doesn't
// satisfy the query.
func selectClaims(query dcql.CredentialQuery, resolved map[string]map[string]any) []dcql.Claim {
	// Unreachable through FindCandidates, which refuses a claim-less mso_mdoc
	// query outright (see the comment there). Kept as a no-match rather than
	// dropped so a future caller cannot reach the empty-disclosure behaviour by
	// bypassing that check.
	if len(query.Claims) == 0 {
		return nil
	}

	if len(query.ClaimSets) == 0 {
		for _, claim := range query.Claims {
			if !claimMatches(claim, resolved) {
				return nil
			}
		}
		return query.Claims
	}

	claimById := make(map[string]dcql.Claim, len(query.Claims))
	for _, claim := range query.Claims {
		if claim.Id != "" {
			claimById[claim.Id] = claim
		}
	}

	for _, set := range query.ClaimSets {
		var matched []dcql.Claim
		allFound := true
		for _, id := range set {
			claim, ok := claimById[id]
			if !ok || !claimMatches(claim, resolved) {
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

func claimMatches(claim dcql.Claim, resolved map[string]map[string]any) bool {
	namespace, elementIdentifier, err := mdocPathParts(claim.Path)
	if err != nil {
		return false
	}
	nsMap, ok := resolved[namespace]
	if !ok {
		return false
	}
	val, ok := nsMap[elementIdentifier]
	if !ok {
		return false
	}
	if len(claim.Values) == 0 {
		return true
	}
	for _, want := range claim.Values {
		if dcql.ClaimValuesEqual(val, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Selective disclosure
// ---------------------------------------------------------------------------

// selectiveDiscloseByPaths reveals exactly the [namespace, elementIdentifier]
// pairs in claimPaths, grouping by namespace since mdoc.SelectiveDisclose
// only reveals within a single namespace at a time, then merging the
// per-namespace results into one MDoc. The AV Blueprint profile only ever
// has a single namespace, but this stays correct for any doctype with more.
func selectiveDiscloseByPaths(doc *stdmdoc.MDoc, claimPaths [][]any) (*stdmdoc.MDoc, error) {
	revealByNamespace := make(map[string][]string)
	var namespaceOrder []string
	for _, path := range claimPaths {
		// Refused rather than skipped: skipping would build a DeviceResponse
		// disclosing one element fewer than the plan the user consented to, and
		// nothing downstream can tell that apart from a verifier asking for less.
		// Unreachable via FindCandidates, which refuses such a query up front;
		// this is the second half of that check, for callers that build paths
		// themselves.
		namespace, elementIdentifier, err := mdocPathParts(path)
		if err != nil {
			return nil, err
		}
		if _, seen := revealByNamespace[namespace]; !seen {
			namespaceOrder = append(namespaceOrder, namespace)
		}
		revealByNamespace[namespace] = append(revealByNamespace[namespace], elementIdentifier)
	}

	merged := *doc
	merged.IssuerSigned.NameSpaces = make(map[string][]stdmdoc.Tag24Item, len(namespaceOrder))
	for _, namespace := range namespaceOrder {
		disclosed, err := stdmdoc.SelectiveDisclose(doc, namespace, revealByNamespace[namespace])
		if err != nil {
			return nil, err
		}
		merged.IssuerSigned.NameSpaces[namespace] = disclosed.IssuerSigned.NameSpaces[namespace]
	}
	return &merged, nil
}

// ---------------------------------------------------------------------------
// Display / attribute helpers
// ---------------------------------------------------------------------------

// buildAttributes builds the disclosure-plan attribute preview for a batch:
// one Attribute per matched claim, flat (no nesting, no compound headers --
// unlike SD-JWT, mso_mdoc claims are always exactly [namespace,
// elementIdentifier], so there's nothing to walk or flatten).
func buildAttributes(batch *models.CredentialBatch, claims []dcql.Claim, resolved map[string]map[string]any, locale string) []clientmodels.Attribute {
	attrs := make([]clientmodels.Attribute, 0, len(claims))
	seen := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		namespace, elementIdentifier, err := mdocPathParts(claim.Path)
		if err != nil {
			continue
		}
		key := clientmodels.ClaimPathKey(claim.Path)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		var value *clientmodels.AttributeValue
		if nsMap, ok := resolved[namespace]; ok {
			value = clientmodels.NewAttributeValue(nsMap[elementIdentifier])
		}

		dn := claimDisplayName(batch, namespace, elementIdentifier, locale)

		// Always set, never omitted when false: the consent screen has to be able
		// to tell "the verifier said it will not retain this" from "this format
		// cannot say", and only mso_mdoc can say it at all.
		intentToRetain := claim.IntentToRetain

		attr := clientmodels.Attribute{
			ClaimPath:      []any{namespace, elementIdentifier},
			DisplayName:    dn,
			Value:          value,
			IntentToRetain: &intentToRetain,
		}
		if len(claim.Values) > 0 {
			attr.RequestedValue = value
		}
		attrs = append(attrs, attr)
	}
	return attrs
}

// unobtainableDescriptor builds a CredentialDescriptor for a doctype the
// wallet has never seen, purely from the DCQL query's own claim paths (see
// FindCandidates' file comment on why there's no metadata fetch here).
func unobtainableDescriptor(docType string, query dcql.CredentialQuery) *clientmodels.CredentialDescriptor {
	attrs := make([]clientmodels.Attribute, 0, len(query.Claims))
	for _, claim := range query.Claims {
		namespace, elementIdentifier, err := mdocPathParts(claim.Path)
		if err != nil {
			continue
		}
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath: []any{namespace, elementIdentifier},
		})
	}
	return &clientmodels.CredentialDescriptor{
		CredentialId: docType,
		Attributes:   attrs,
	}
}

// credentialImage loads the credential logo that resolves for the locale
// from the batch's display metadata, mirroring eudi_sdjwt_dcql's identical
// helper.
func (h *MdocDcqlHandler) credentialImage(batch *models.CredentialBatch, locale string) *clientmodels.Image {
	if batch.CredentialMetadata == nil {
		return nil
	}
	logoManager := h.storage.FileSystem().Credentials().LogoManager()
	return services.LoadResolvedLogo(logoManager, services.CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale)
}

// issuerTrustedParty builds a TrustedParty from the stored issuer display
// metadata, mirroring eudi_sdjwt_dcql's identical helper.
func (h *MdocDcqlHandler) issuerTrustedParty(batch *models.CredentialBatch, locale string) clientmodels.TrustedParty {
	return clientmodels.TrustedParty{
		Id:       batch.CredentialIssuerIdentifier,
		Name:     clientmodels.Resolve(services.IssuerNamesByLanguage(batch.IssuerDisplay), locale),
		Image:    h.issuerImage(batch, locale),
		Verified: batch.IssuerVerified,
	}
}

// issuerImage loads the issuer logo that resolves for the locale from the
// batch's issuer display metadata, mirroring eudi_sdjwt_dcql's identical
// helper.
func (h *MdocDcqlHandler) issuerImage(batch *models.CredentialBatch, locale string) *clientmodels.Image {
	logoManager := h.storage.FileSystem().Issuers().LogoManager()
	return services.LoadResolvedLogo(logoManager, services.IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale)
}

// credentialDisplayName resolves a credential's display name from its stored
// metadata, falling back to the docType when there is no display metadata.
func credentialDisplayName(batch *models.CredentialBatch, locale string) string {
	if batch.CredentialMetadata != nil {
		if ts := services.CredentialNamesByLanguage(batch.CredentialMetadata.Display); len(ts) > 0 {
			return clientmodels.Resolve(ts, locale)
		}
	}
	return batch.VerifiableCredentialType
}

// claimDisplayName resolves a claim's display name from the stored credential
// metadata. mdoc claim paths are always exactly [namespace, elementIdentifier],
// so no wildcard handling is ever needed here, unlike eudi_sdjwt_dcql's
// generic claimPathMatchesMetadataPath-based version.
//
// A bare [elementIdentifier] path is accepted as a fallback, because the stored
// path is whatever the issuer published: convertCredentialMetadata writes
// credential_metadata.claims[].path through verbatim, and the AV profile
// specifies no display metadata at all, so nothing obliges an issuer to use the
// two-component form. Without the fallback a one-component path matches nothing
// and the attribute silently renders with no label — no error, no log, and the
// credential's own name still resolving, which is a hard failure to attribute to
// the issuer's metadata. The fallback only applies once the exact match has been
// ruled out across every claim, so a correctly published path always wins.
//
// The credential list needs the same rule for the same reason and applies it
// separately, in services.ResolveBatchDisplay (aliasMdocBareElementPaths): it
// resolves names by claim-path key rather than per claim, so it cannot call this.
// If the rule changes, change both — the two views disagreeing about one claim is
// exactly the bug that motivated it.
//
// Once the metadata has nothing to say, the identifier itself is the last
// resort: services.DerivedMdocClaimName names an age_over_NN the issuer never
// advertised. The credential list gets that from addDerivedMdocClaimNames, on
// the same "change both" footing as the rule above.
func claimDisplayName(batch *models.CredentialBatch, namespace, elementIdentifier string, locale string) *string {
	if dn := publishedClaimDisplayName(batch, namespace, elementIdentifier, locale); dn != nil {
		return dn
	}
	if name, ok := services.DerivedMdocClaimName(elementIdentifier); ok {
		return &name
	}
	// Nothing names this element, so name it after itself. The consent screen and
	// the activity log both render whatever this returns, and a nil name leaves
	// the row's identity to the app — an element the issuer never declared would
	// then be asked for, or recorded as disclosed, with nothing on screen saying
	// which one. The raw identifier is poor text but it names the right thing,
	// and it matches what addDerivedMdocClaimNames does for the credential list.
	return &elementIdentifier
}

// publishedClaimDisplayName is claimDisplayName restricted to what the issuer
// actually published, yielding nil when its metadata names this claim nowhere.
func publishedClaimDisplayName(batch *models.CredentialBatch, namespace, elementIdentifier string, locale string) *string {
	if batch.CredentialMetadata == nil {
		return nil
	}

	// Display rows of the first bare-element path matching this element, used
	// only if no exact [namespace, elementIdentifier] path matches.
	var fallbackDisplay []models.ClaimDisplay

	for _, claim := range batch.CredentialMetadata.Claims {
		if len(claim.Display) == 0 {
			continue
		}
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}

		if ns, el, err := mdocPathParts(path); err == nil {
			if ns == namespace && el == elementIdentifier {
				return resolveClaimName(claim.Display, locale)
			}
			continue
		}

		if el, ok := bareElementPath(path); ok && el == elementIdentifier && fallbackDisplay == nil {
			fallbackDisplay = claim.Display
		}
	}

	if fallbackDisplay == nil {
		return nil
	}

	// Worth a warning rather than a silent recovery: the label is only rendered
	// because the wallet guessed the namespace the issuer left out, and the fix
	// belongs in the issuer's metadata.
	eudi.Logger.Warnf(
		"credential %q labels claim %q with a one-component path [%q]; mdoc claim paths should be [%q, %q]",
		batch.VerifiableCredentialType, elementIdentifier, elementIdentifier, namespace, elementIdentifier)

	return resolveClaimName(fallbackDisplay, locale)
}

// bareElementPath reports the element identifier of a one-component claim path,
// the shape an issuer publishes when it treats an mdoc element like a flat
// SD-JWT claim name.
func bareElementPath(path []any) (elementIdentifier string, ok bool) {
	if len(path) != 1 {
		return "", false
	}
	el, isString := path[0].(string)
	if !isString {
		return "", false
	}
	return el, true
}

// resolveClaimName resolves the locale-appropriate name out of a claim's display
// rows, yielding nil when the rows carry no usable name.
func resolveClaimName(display []models.ClaimDisplay, locale string) *string {
	if ts := services.ClaimNamesByLanguage(display); len(ts) > 0 {
		return clientmodels.ResolvePtr(ts, locale)
	}
	return nil
}

func (h *MdocDcqlHandler) buildLogCredential(batch *models.CredentialBatch, claimPaths [][]any, resolved map[string]map[string]any) clientmodels.LogCredential {
	locale := h.currentLocale.Get()
	attrs := make([]clientmodels.Attribute, 0, len(claimPaths))
	seen := make(map[string]struct{}, len(claimPaths))
	for _, path := range claimPaths {
		namespace, elementIdentifier, err := mdocPathParts(path)
		if err != nil {
			continue
		}
		key := clientmodels.ClaimPathKey(path)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		var value *clientmodels.AttributeValue
		if nsMap, ok := resolved[namespace]; ok {
			value = clientmodels.NewAttributeValue(nsMap[elementIdentifier])
		}
		dn := claimDisplayName(batch, namespace, elementIdentifier, locale)
		attrs = append(attrs, clientmodels.Attribute{
			ClaimPath:   []any{namespace, elementIdentifier},
			DisplayName: dn,
			Value:       value,
		})
	}

	log := clientmodels.LogCredential{
		CredentialId: batch.VerifiableCredentialType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
		Name:         credentialDisplayName(batch, locale),
		Image:        h.credentialImage(batch, locale),
		Issuer:       h.issuerTrustedParty(batch, locale),
		Attributes:   attrs,
		ExpiryDate:   dcql.BatchExpiryUnix(batch),
	}
	if batch.IssuedAt.Valid {
		x := batch.IssuedAt.V.Unix()
		log.IssuanceDate = &x
	}
	return log
}
