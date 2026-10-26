// Package eudi_vcdm_dcql is the DCQL query handler for SD-JWT-secured W3C VCDM
// 2.0 (vc+sd-jwt) credentials in the eudi SQLite storage. It is a thin routing
// shell over the shared sdjwtdcql.Engine — the same machinery the SD-JWT VC
// handler uses, differing only in format routing and credentialSubject-rooted
// claim scoping.
package eudi_vcdm_dcql

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwtdcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
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
// was linked to the instance at VCDM receipt. A disclosed credential is enveloped
// in a Verifiable Presentation signed with the holder key from its cnf
// (vcdmsdjwt.CreateEnvelopedPresentation), instead of carrying a KB-JWT. The SD-JWT VC type-metadata fetchers do not apply to VCDM (a
// verifier targets a VCDM credential by its composite @context+type identity,
// not a fetchable vct URL), so the "obtainable descriptor" path stays disabled:
// a VCDM query matching no stored credential simply yields no owned candidate.
// A revoked credential is still offered, flagged by the revocation checker.
func NewVcdmDcqlHandler(
	eudiStorage storage.Storage,
	credentialStore db.VcdmStore,
	keyBinder sdjwt.KeyBinder,
	currentLocale *clientmodels.CurrentLocale,
	revocation sdjwtdcql.VcdmRevocationChecker,
) *Handler {
	profile := sdjwtdcql.NewProfile(
		models.CredentialFormatSdJwtVcdm,
		clientmodels.Format_SdJwtVcdm,
		func(key string) bool {
			return key == vcdm.CredentialSubjectKey
		},
		vcdmsdjwt.CreateEnvelopedPresentation,
	)
	return &Handler{sdjwtdcql.NewEngine(profile, eudiStorage, sdjwtdcql.NewVcdmBatchStore(credentialStore, revocation), nil, nil, keyBinder, currentLocale)}
}

// CanHandleCredentialQuery claims every vc+sd-jwt query. Unlike SD-JWT VC there
// is no IRMA path, so no vct-shape exclusion applies.
func (h *Handler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(models.CredentialFormatSdJwtVcdm)
}
