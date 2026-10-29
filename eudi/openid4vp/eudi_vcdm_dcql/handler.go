// Package eudi_vcdm_dcql is the DCQL query handler for SD-JWT-secured W3C VCDM
// 2.0 (vc+sd-jwt) credentials in the eudi SQLite storage. It is a thin routing
// shell over the shared sdjwtdcql.Engine — the same machinery the SD-JWT VC
// handler uses, differing only in format routing and credentialSubject-rooted
// claim scoping.
package eudi_vcdm_dcql

import (
	"encoding/json"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwtdcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// Handler serves DCQL queries for SD-JWT-secured W3C VCDM 2.0 (vc+sd-jwt)
// credentials. It embeds the shared engine — gaining FindCandidates and
// PrepareDisclosure — and adds VCDM routing.
type Handler struct {
	*sdjwtdcql.Engine
}

var _ dcql.DcqlCredentialQueryHandler = (*Handler)(nil)

// NewVcdmDcqlHandler creates the VCDM handler over the VCDM store. keyBinder is
// the same holder key signer the SD-JWT VC handler uses — the holder private key
// was linked to the instance at VCDM receipt. With holder binding, a disclosed
// credential is enveloped in a Verifiable Presentation signed with the holder
// key from its cnf, instead of carrying a KB-JWT; without it, the SD-JWT is sent
// as is.
//
// The SD-JWT VC type-metadata fetchers do not apply to VCDM (a verifier targets
// a VCDM credential by its composite @context+type identity, not a fetchable
// vct URL), so the "obtainable descriptor" path stays disabled: a VCDM query
// matching no stored credential simply yields no owned candidate.
//
// revocation decides each candidate's Revoked flag from the status the
// revocation sweep last stored, as for every format. A revoked credential is
// still offered, flagged.
func NewVcdmDcqlHandler(
	eudiStorage storage.Storage,
	credentialStore db.VcdmStore,
	keyBinder sdjwt.KeyBinder,
	currentLocale *clientmodels.CurrentLocale,
	revocation sdjwtdcql.RevocationChecker,
) *Handler {
	profile := sdjwtdcql.Profile{
		StorageFormat: models.CredentialFormatSdJwtVcdm,
		ClientFormat:  clientmodels.Format_SdJwtVcdm,
		IsUserDataKey: func(key string) bool {
			return key == vcdm.CredentialSubjectKey
		},
		Present:           vcdmsdjwt.CreateEnvelopedPresentation,
		MatchesTypeValues: matchesTypeValues,
		FallbackName:      fallbackName,
	}
	return &Handler{sdjwtdcql.NewEngine(profile, eudiStorage, sdjwtdcql.NewVcdmBatchStore(credentialStore, revocation), nil, nil, keyBinder, currentLocale)}
}

// CanHandleCredentialQuery claims every vc+sd-jwt query. Unlike SD-JWT VC there
// is no IRMA path, so no vct-shape exclusion applies.
func (h *Handler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(models.CredentialFormatSdJwtVcdm)
}

// matchesTypeValues matches a stored credential's JSON-LD `type` against DCQL
// type_values (OpenID4VP §B.1.1).
//
// The @context / JSON-LD processing rules honored here, within the wallet's
// lightweight (non-dereferencing, §6.3) model:
//
//   - `type` is a JSON-LD @type SET: the match is order-independent and by
//     membership. A credential satisfies an inner array when its type set is a
//     SUPERSET of it (every requested type present); the outer array is a
//     disjunction. An empty inner array is ignored rather than matching all.
//   - Type values are compared as literal strings (terms or IRIs). We do NOT
//     dereference `@context` to expand terms into IRIs, so verifier and issuer
//     must share the term vocabulary — guaranteed for the core term
//     VerifiableCredential by VCDM 2.0's mandatory base context (ContextV2,
//     enforced at receipt by vcdm.Document.Validate), and assumed for domain
//     terms via a shared domain `@context`.
//   - The comparison is against the `type` array only. The credential's
//     `@context` is part of its stored identity (CredentialType), but §B.1.1
//     constrains `type`, so @context is intentionally not folded in here.
func matchesTypeValues(batch *sdjwtdcql.Batch, typeValues [][]string) bool {
	var doc vcdm.Document
	if err := json.Unmarshal([]byte(batch.ProcessedPayload), &doc); err != nil {
		return false
	}
	for _, requested := range typeValues {
		if len(requested) == 0 {
			continue
		}
		all := true
		for _, t := range requested {
			if !doc.HasType(t) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// fallbackName is the credential's own `name`, for a credential whose
// metadata gives it none.
func fallbackName(batch *sdjwtdcql.Batch, locale string) string {
	return services.VcdmPayloadName(batch.ProcessedPayload, locale)
}
