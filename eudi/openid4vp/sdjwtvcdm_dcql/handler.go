// Package sdjwtvcdm_dcql is the DCQL query handler for SD-JWT-secured W3C VCDM
// 2.0 (vc+sd-jwt) credentials in the eudi SQLite storage. It is a thin routing
// shell over the shared sdjwt_dcql.Engine — the same machinery the SD-JWT VC
// handler uses, differing only in format routing and credentialSubject-rooted
// claim scoping.
package sdjwtvcdm_dcql

import (
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwt_dcql"
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
	*sdjwt_dcql.Engine
}

var _ dcql.DcqlCredentialQueryHandler = (*Handler)(nil)

// New creates the VCDM handler over the VCDM store. keyBinder is
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
func New(
	eudiStorage storage.Storage,
	credentialStore db.VcdmStore,
	keyBinder sdjwt.KeyBinder,
	currentLocale *clientmodels.CurrentLocale,
	revocation sdjwt_dcql.RevocationChecker,
) *Handler {
	profile := sdjwt_dcql.Profile{
		StorageFormat: models.CredentialFormatSdJwtVcdm,
		ClientFormat:  clientmodels.Format_SdJwtVcdm,
		IsUserDataKey: func(key string) bool {
			return key == vcdm.CredentialSubjectKey
		},
		Present:           vcdmsdjwt.CreateEnvelopedPresentation,
		MatchesTypeValues: matchesTypeValues,
		FallbackName:      fallbackName,
	}
	return &Handler{sdjwt_dcql.NewEngine(profile, eudiStorage, sdjwt_dcql.NewVcdmBatchStore(credentialStore, revocation), nil, nil, keyBinder, currentLocale)}
}

// CanHandleCredentialQuery claims every vc+sd-jwt query. Unlike SD-JWT VC there
// is no IRMA path, so no vct-shape exclusion applies.
func (h *Handler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(models.CredentialFormatSdJwtVcdm)
}

// matchesTypeValues matches a stored credential's types against DCQL
// type_values (OpenID4VP Appendix B.1.1):
//
//   - Both sides are fully expanded types: the credential's `type` with its
//     `@context` applied, expanded once at issuance (vcdm.ExpandTypes), against
//     the IRIs the verifier lists. A compact term such as "VerifiableCredential"
//     in a query only matches a type no context defines, which stays as written.
//   - `type` is a JSON-LD @type set: the match is order-independent and by
//     membership. A credential satisfies an inner array when its types include
//     every type in it; the outer array is a disjunction. An empty inner array
//     is ignored rather than matching all.
//   - A credential stored before the wallet expanded types has none, so it
//     matches no type_values query until it is issued again.
func matchesTypeValues(batch *sdjwt_dcql.Batch, typeValues [][]string) bool {
	for _, requested := range typeValues {
		if len(requested) == 0 {
			continue
		}
		all := true
		for _, t := range requested {
			if !slices.Contains(batch.ExpandedTypes, t) {
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
func fallbackName(batch *sdjwt_dcql.Batch, locale string) string {
	return services.VcdmPayloadName(batch.ProcessedPayload, locale)
}
