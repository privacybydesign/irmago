// Package eudi_sdjwt_dcql is the DCQL query handler for IETF SD-JWT VC
// (dc+sd-jwt) credentials in the eudi SQLite storage (issued via OpenID4VCI).
// It is a thin routing shell over the shared sdjwtdcql.Engine.
package eudi_sdjwtvc_dcql

import (
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwtdcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// Handler serves DCQL queries for IETF SD-JWT VC (dc+sd-jwt) credentials. It
// embeds the shared engine — gaining FindCandidates and PrepareDisclosure — and
// adds SD-JWT-VC-specific routing.
type Handler struct {
	*sdjwtdcql.Engine
}

var _ dcql.DcqlCredentialQueryHandler = (*Handler)(nil)

// NewSdJwtVcDcqlHandler creates the SD-JWT VC handler. vctFetcher and
// issuerFetcher describe credentials the wallet has never seen (the "obtainable
// descriptor" path); pass nil to disable it. keyBinder is the KB-JWT signer used
// when a presentation requires holder binding — e.g.
// sdjwt.NewDefaultKeyBinder(services.NewHolderBindingKeyService(eudiStorage.Db())).
func NewSdJwtVcDcqlHandler(
	eudiStorage storage.Storage,
	credentialStore db.CredentialStore,
	vctFetcher typemetadata.VctFetcher,
	issuerFetcher typemetadata.IssuerFetcher,
	keyBinder sdjwt.KeyBinder,
	currentLocale *clientmodels.CurrentLocale,
	revocation sdjwtdcql.RevocationChecker,
) *Handler {
	profile := sdjwtdcql.NewProfile(
		models.CredentialFormatSdJwtVc,
		clientmodels.Format_SdJwtVc,
		func(key string) bool {
			_, std := sdjwtvc.StandardClaims[key]
			return !std
		},
	)
	return &Handler{sdjwtdcql.NewEngine(profile, eudiStorage, credentialStore, vctFetcher, issuerFetcher, keyBinder, currentLocale, revocation)}
}

// CanHandleCredentialQuery claims dc+sd-jwt queries whose vct_values are not
// 3-component IRMA scheme identifiers (those are served by irma_sdjwt_dcql
// against the BBolt store). URL and URN vcts — and any other non-IRMA-shaped
// identifier, and queries without vct_values — route here so the EUDI store
// still gets searched.
//
// The discrimination is purely structural — there is no semantic check that the
// URL/URN is reachable, that the URN sits in any recognised namespace, or that
// the store actually holds the requested type. See isIrmaStyleVct.
func (h *Handler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	if query.Format != string(models.CredentialFormatSdJwtVc) {
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
