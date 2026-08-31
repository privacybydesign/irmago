package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/mdoc_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/testdata"
)

// The EU Age Verification profile's docType. Five dot-separated parts, where a
// Yivi scheme identifier has three — the shape that made the authorized-set
// matching in eudi/scheme worth its own regression test.
const avDocType = "eu.europa.ec.av.1"

// avRelyingPartySchemeData is what a correctly issued relying party certificate
// carries for this credential: an authorized set naming the docType and the one
// element the query asks for. This is the whole point of the test — the
// authorization check runs for real and passes because the certificate genuinely
// permits the query, not because anything was switched off.
const avRelyingPartySchemeData = `{
	"registration": "https://portal.yivi.app/organizations/av-test",
	"organization": { "legalName": { "en": "Age Verification Test Verifier" } },
	"rp": {
		"authorized": [
			{ "credential": "eu.europa.ec.av.1", "attributes": ["age_over_18"] }
		],
		"purpose": { "en": "Age verification" }
	}
}`

// unrelatedRelyingPartySchemeData authorizes a different credential entirely, so
// the same request has to be refused. This reproduces the error an unprepared
// staging certificate produces against an mdoc age query.
const unrelatedRelyingPartySchemeData = `{
	"registration": "https://portal.yivi.app/organizations/av-test",
	"organization": { "legalName": { "en": "Age Verification Test Verifier" } },
	"rp": {
		"authorized": [
			{ "credential": "test.test.email", "attributes": ["email"] }
		],
		"purpose": { "en": "Age verification" }
	}
}`

// TestOpenID4VP_MdocAgeVerification covers an mso_mdoc age-verification
// presentation across the two stages that decide it, both with the production
// code paths intact: whether the relying party is authorized to ask (its
// certificate's authorized sets, checked by the real SchemeQueryValidator), and
// whether the wallet can answer (a genuinely issued mdoc in storage, matched by
// mdoc_dcql).
//
// Those two stages fail independently and their errors look nothing alike, which
// is what makes them worth pinning together: an unauthorized certificate reports
// the credential as unauthorized, while an empty store reports nothing at all and
// renders the raw docType as an "unobtainable" credential instead.
func TestOpenID4VP_MdocAgeVerification(t *testing.T) {
	t.Run("an authorized relying party certificate permits the age query", testMdocAv_AuthorizedCertificate_PermitsQuery)
	t.Run("a certificate authorizing another credential refuses the age query", testMdocAv_UnrelatedCertificate_RefusesQuery)
	t.Run("an issued mdoc is offered as an owned candidate", testMdocAv_IssuedCredential_IsOwnedCandidate)
	t.Run("without the credential the query yields an unobtainable descriptor", testMdocAv_WithoutCredential_IsUnobtainable)
	t.Run("stored display metadata names the credential and its claim", testMdocAv_DisplayMetadata_NamesCredentialAndClaim)
	t.Run("display metadata resolves per locale", testMdocAv_DisplayMetadata_ResolvesPerLocale)
	t.Run("one credential's text never mixes languages", testMdocAv_DisplayMetadata_DoesNotMixLanguages)
	t.Run("a one-component claim path still resolves the claim label", testMdocAv_BareClaimPath_StillResolvesLabel)
	t.Run("a two-component path wins over a bare one for the same element", testMdocAv_ExactClaimPath_WinsOverBarePath)
	t.Run("any advertised age_over_NN is taken in and disclosable", testMdocAv_AcceptsAnyAdvertisedThreshold)
}

func testMdocAv_AuthorizedCertificate_PermitsQuery(t *testing.T) {
	authRequestJwt, validator := setupMdocAvVerifier(t, avRelyingPartySchemeData)

	request, leafCert, requestorInfo, err := validator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, leafCert)
	require.Equal(t, "Age Verification Test Verifier", requestorInfo.Organization.LegalName["en"])

	// The query survived authorization intact, still naming the mdoc docType and
	// the two-component claim path mdoc matching requires.
	require.Len(t, request.DcqlQuery.Credentials, 1)
	credentialQuery := request.DcqlQuery.Credentials[0]
	require.Equal(t, string(clientmodels.Format_MsoMdoc), credentialQuery.Format)
	require.NotNil(t, credentialQuery.Meta)
	require.Equal(t, avDocType, credentialQuery.Meta.DocTypeValue)
	require.Equal(t, []string{"age_over_18"}, credentialQuery.AuthorizationAttributeNames())
}

func testMdocAv_UnrelatedCertificate_RefusesQuery(t *testing.T) {
	authRequestJwt, validator := setupMdocAvVerifier(t, unrelatedRelyingPartySchemeData)

	_, _, _, err := validator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(),
		`failed to verify queried credentials: credential is not authorized: credential eu.europa.ec.av.1 is not in the authorized set`)
}

func testMdocAv_IssuedCredential_IsOwnedCandidate(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)
	storeIssuedAvMdoc(t, eudiStorage)

	handler := newAvMdocHandler(t, eudiStorage)
	query := avCredentialQuery(t)

	require.True(t, handler.CanHandleCredentialQuery(query))

	result, err := handler.FindCandidates(query)

	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "the issued mdoc must be offered for disclosure")
	require.Empty(t, result.ObtainableDescriptors,
		"a credential the wallet owns must not also be advertised as obtainable")

	candidate := result.OwnedCandidates[0]
	require.Equal(t, avDocType, candidate.CredentialId)
	require.Equal(t, clientmodels.Format_MsoMdoc, candidate.Format)
	require.Len(t, candidate.Attributes, 1)
	require.Equal(t, []any{avDocType, "age_over_18"}, candidate.Attributes[0].ClaimPath)

	// No display metadata was stored, so both names fall back rather than error:
	// the credential renders as its raw docType, and the claim gets the name
	// services.DerivedMdocClaimName reads out of the element identifier, which is
	// all an age_over_NN needs. This is the contrast the next two subtests measure
	// against -- they check that published metadata displaces both fallbacks.
	require.Equal(t, avDocType, candidate.Name)
	require.NotNil(t, candidate.Attributes[0].DisplayName)
	require.Equal(t, "Age Over 18", *candidate.Attributes[0].DisplayName)
}

func testMdocAv_DisplayMetadata_NamesCredentialAndClaim(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)
	storeIssuedAvMdoc(t, eudiStorage, withAvDisplayMetadata)

	handler := newAvMdocHandler(t, eudiStorage)

	result, err := handler.FindCandidates(avCredentialQuery(t))

	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	candidate := result.OwnedCandidates[0]
	require.Equal(t, "Proof of Age", candidate.Name,
		"the stored credential display name must win over the raw docType")
	require.Equal(t, "Yivi Age Issuer", candidate.Issuer.Name)

	// The assertion this file exists for: the stored claim path is the
	// two-component [namespace, elementIdentifier] mdoc form, so claimDisplayName
	// matches it against the requested namespace and element and finds the label.
	// A one-component ["age_over_18"] path would silently resolve to nil here.
	require.Len(t, candidate.Attributes, 1)
	require.NotNil(t, candidate.Attributes[0].DisplayName)
	require.Equal(t, "Over 18", *candidate.Attributes[0].DisplayName)
}

// testMdocAv_DisplayMetadata_ResolvesPerLocale proves the mdoc display path is
// actually translated rather than merely locale-shaped: the credential name, the
// claim label and the issuer name each follow the wallet's UI locale.
//
// It is worth pinning on the mdoc path specifically even though
// clientmodels.Resolve is tested on its own. The mdoc handler resolves three
// different things through three different helpers — credentialDisplayName,
// claimDisplayName and issuerTrustedParty — and a helper that forgot to pass the
// locale, or passed a snapshot of it, would still return correct English and pass
// every single-locale test in this file.
//
// The fallback cases matter as much as the hits. An issuer publishing no
// translation for the user's language must not blank the field: the wallet shows
// the credential in the language it has rather than showing nothing, which is why
// the chain ends at English and then at any translation at all.
func testMdocAv_DisplayMetadata_ResolvesPerLocale(t *testing.T) {
	tests := []struct {
		name           string
		locale         string
		credentialName string
		claimLabel     string
		issuerName     string
	}{
		{
			name:           "english resolves the english bundle",
			locale:         "en",
			credentialName: "Proof of Age",
			claimLabel:     "Over 18",
			issuerName:     "Yivi Age Issuer",
		},
		{
			name:           "dutch resolves the dutch bundle",
			locale:         "nl",
			credentialName: "Leeftijdsbewijs",
			claimLabel:     "Ouder dan 18",
			issuerName:     "Yivi Leeftijdsuitgever",
		},
		{
			// The base-language step of the chain: nl-BE is not published, nl is.
			name:           "a regional locale falls back to its base language",
			locale:         "nl-BE",
			credentialName: "Leeftijdsbewijs",
			claimLabel:     "Ouder dan 18",
			issuerName:     "Yivi Leeftijdsuitgever",
		},
		{
			// Neither the locale nor its base language is published, so the chain
			// reaches English rather than leaving the user with empty labels.
			name:           "an unpublished locale falls back to english",
			locale:         "de",
			credentialName: "Proof of Age",
			claimLabel:     "Over 18",
			issuerName:     "Yivi Age Issuer",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eudiStorage := newTestEudiStorage(t)
			storeIssuedAvMdoc(t, eudiStorage, withAvDisplayMetadataInTwoLocales)

			handler := newAvMdocHandlerForLocale(t, eudiStorage, test.locale)

			result, err := handler.FindCandidates(avCredentialQuery(t))

			require.NoError(t, err)
			require.Len(t, result.OwnedCandidates, 1)

			candidate := result.OwnedCandidates[0]
			require.Equal(t, test.credentialName, candidate.Name)
			require.Equal(t, test.issuerName, candidate.Issuer.Name)

			require.Len(t, candidate.Attributes, 1)
			require.NotNil(t, candidate.Attributes[0].DisplayName,
				"a published claim label must resolve for every locale, by fallback if not directly")
			require.Equal(t, test.claimLabel, *candidate.Attributes[0].DisplayName)
		})
	}
}

// One object's text must not mix languages. A credential whose name resolved to
// Dutch while its claim label resolved to English would read as a bug to the
// user, and is the failure mode a per-field fallback invites.
func testMdocAv_DisplayMetadata_DoesNotMixLanguages(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)
	storeIssuedAvMdoc(t, eudiStorage, withAvDisplayMetadataInTwoLocales)

	handler := newAvMdocHandlerForLocale(t, eudiStorage, "nl")

	result, err := handler.FindCandidates(avCredentialQuery(t))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	candidate := result.OwnedCandidates[0]
	require.Len(t, candidate.Attributes, 1)
	require.NotNil(t, candidate.Attributes[0].DisplayName)

	dutch := []string{candidate.Name, candidate.Issuer.Name, *candidate.Attributes[0].DisplayName}
	for _, text := range dutch {
		require.NotContains(t, []string{"Proof of Age", "Over 18", "Yivi Age Issuer"}, text,
			"no English string may survive into a Dutch rendering of the same credential")
	}
}

// testMdocAv_BareClaimPath_StillResolvesLabel covers the metadata an issuer
// publishes when it treats the mdoc element like a flat SD-JWT claim name:
// ["age_over_18"] instead of ["eu.europa.ec.av.1", "age_over_18"].
//
// Nothing forbids that. convertCredentialMetadata stores the published path
// verbatim, and the AV profile specifies no display metadata at all, so there is
// no shape to conform to. Before the bare-path fallback this resolved to no label
// at all -- with the credential name still resolving, no error and no log, which
// reads in the app as a display bug in the wallet rather than as issuer metadata
// missing a namespace.
func testMdocAv_BareClaimPath_StillResolvesLabel(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)
	storeIssuedAvMdoc(t, eudiStorage, withAvBareClaimPathMetadata)

	handler := newAvMdocHandler(t, eudiStorage)

	result, err := handler.FindCandidates(avCredentialQuery(t))

	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	candidate := result.OwnedCandidates[0]
	require.Len(t, candidate.Attributes, 1)
	require.NotNil(t, candidate.Attributes[0].DisplayName,
		"a one-component path must still label the element it names")
	require.Equal(t, "Over 18", *candidate.Attributes[0].DisplayName)
}

// testMdocAv_ExactClaimPath_WinsOverBarePath pins the precedence between the two
// accepted shapes. The fallback exists to rescue incomplete metadata, so it must
// never override a path the issuer spelled out in full -- including when the bare
// row is stored first and would be reached earlier by the scan.
func testMdocAv_ExactClaimPath_WinsOverBarePath(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)
	storeIssuedAvMdoc(t, eudiStorage, func(batch *models.CredentialBatch) {
		batch.CredentialMetadata = &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				{Name: "Proof of Age", Locale: datatypes.NullString{V: "en", Valid: true}},
			},
			Claims: []models.CredentialClaim{
				{
					Path: datatypes.JSON(`["age_over_18"]`),
					Display: []models.ClaimDisplay{
						{Name: "Bare path label", Locale: datatypes.NullString{V: "en", Valid: true}},
					},
				},
				{
					Path: datatypes.JSON(`["` + avDocType + `", "age_over_18"]`),
					Display: []models.ClaimDisplay{
						{Name: "Over 18", Locale: datatypes.NullString{V: "en", Valid: true}},
					},
				},
			},
		}
	})

	handler := newAvMdocHandler(t, eudiStorage)

	result, err := handler.FindCandidates(avCredentialQuery(t))

	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	candidate := result.OwnedCandidates[0]
	require.Len(t, candidate.Attributes, 1)
	require.NotNil(t, candidate.Attributes[0].DisplayName)
	require.Equal(t, "Over 18", *candidate.Attributes[0].DisplayName,
		"the fully qualified path must win over the bare one")
}

func testMdocAv_WithoutCredential_IsUnobtainable(t *testing.T) {
	// Same query, empty wallet. This is the shape of the failure that reads as a
	// display problem in the app -- the descriptor carries the raw docType and no
	// issuer, because there is no stored credential to take either from.
	handler := newAvMdocHandler(t, newTestEudiStorage(t))

	result, err := handler.FindCandidates(avCredentialQuery(t))

	require.NoError(t, err)
	require.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)

	descriptor := result.ObtainableDescriptors[0]
	require.Equal(t, avDocType, descriptor.CredentialId, "the raw docType stands in for a display name")
	require.Empty(t, descriptor.Name, "there is no display name to resolve without a stored credential")
	require.Len(t, descriptor.Attributes, 1)
	require.Nil(t, descriptor.Attributes[0].DisplayName)

	// The issuer is left at its zero value rather than omitted, which is what an
	// app renders as an unnamed party ("contact unknown"): there is no stored
	// credential to take an issuer from, and the query never carried one.
	require.Empty(t, descriptor.Issuer.Name)
	require.Empty(t, descriptor.Issuer.Id)
	require.False(t, descriptor.Issuer.Verified)
}

// setupMdocAvVerifier builds a relying party certificate carrying the given
// scheme data, trusts its chain, and signs an authorization request asking for
// the age credential.
//
// Unlike setupTest in verifier_validator_test.go this wires the real
// DefaultQueryValidatorFactory rather than the mock: the authorization decision
// is what these subtests are about, so it has to be the production one.
func setupMdocAvVerifier(t *testing.T, schemeData string) (string, *RequestorCertificateStoreVerifierValidator) {
	t.Helper()

	hostname := "av-verifier.example.com"
	crlDistPoint := "https://yivi.app/crl.crl"

	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("AV ROOT CERT"), 1, testdata.PkiOption_None, &crlDistPoint)
	verifierKey, verifierCert, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName("AV VERIFIER CERT"), hostname, caCerts[0], caKeys[0], schemeData, testdata.PkiOption_None)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(caCerts[0])

	trustModel := eudi.NewTestTrustModel(t.TempDir(), rootPool, intermediatePool, nil)
	validator := NewRequestorCertificateStoreVerifierValidator(trustModel, &DefaultQueryValidatorFactory{})

	authRequestJwt := testdata.CreateTestAuthorizationRequestJWT(hostname, verifierKey, verifierCert, func(token *jwt.Token) {
		// The stock test request asks for an SD-JWT email credential; replace it
		// with the mdoc age query this file is about.
		token.Claims.(jwt.MapClaims)["dcql_query"] = map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "age",
					"format": string(clientmodels.Format_MsoMdoc),
					"meta":   map[string]any{"doctype_value": avDocType},
					"claims": []map[string]any{
						{"path": []string{avDocType, "age_over_18"}},
					},
				},
			},
		}
	})

	return authRequestJwt, validator
}

// avCredentialQuery is the same query setupMdocAvVerifier signs into the
// authorization request, as the parsed dcql type the handler consumes. Built by
// round-tripping the JSON so the handler is fed what the wire would actually
// produce rather than a hand-populated struct.
func avCredentialQuery(t *testing.T) dcql.CredentialQuery {
	t.Helper()

	return avCredentialQueryForElement(t, "age_over_18")
}

// avCredentialQueryForElement is avCredentialQuery for a threshold other than the
// mandatory one. The AV profile enumerates no thresholds, so nothing here may
// assume the set an issuer publishes.
func avCredentialQueryForElement(t *testing.T, element string) dcql.CredentialQuery {
	t.Helper()

	raw := `{
		"id": "age",
		"format": "mso_mdoc",
		"meta": { "doctype_value": "` + avDocType + `" },
		"claims": [ { "path": ["` + avDocType + `", "` + element + `"] } ]
	}`

	var query dcql.CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(raw), &query))
	return query
}

// The AV profile fixes age_over_18 as the only mandatory element and leaves every
// other age_over_NN to the issuer, without enumerating them. So the wallet must
// take in and disclose any threshold the issuer advertises and signs, including
// one outside the thirteen the EU reference issuer happens to publish -- there is
// nothing anywhere in irmago that may hold an allowed list.
//
// Exercised through the real path: a genuinely signed mdoc under a fresh
// IACA/document-signer hierarchy, stored the way issuance stores it, then matched
// by a DCQL query naming the threshold.
func testMdocAv_AcceptsAnyAdvertisedThreshold(t *testing.T) {
	eudiStorage := newTestEudiStorage(t)

	storeIssuedAvMdocWithElements(t,
		eudiStorage,
		map[string]any{"age_over_18": true, "age_over_39": true},
		func(batch *models.CredentialBatch) {
			withAvDisplayMetadata(batch)
			// The issuer advertises the unusual threshold alongside the mandatory
			// one, which is the case this is about: nothing may treat a claim as
			// unknown for being outside a set irmago never had.
			batch.CredentialMetadata.Claims = append(batch.CredentialMetadata.Claims,
				models.CredentialClaim{
					Path: datatypes.JSON(`["` + avDocType + `", "age_over_39"]`),
					Display: []models.ClaimDisplay{
						{Name: "Over 39", Locale: datatypes.NullString{V: "en", Valid: true}},
					},
				})
		})

	handler := newAvMdocHandler(t, eudiStorage)
	query := avCredentialQueryForElement(t, "age_over_39")

	require.True(t, handler.CanHandleCredentialQuery(query))

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1,
		"a credential carrying the requested threshold must be offered for disclosure")
	require.Empty(t, result.ObtainableDescriptors)

	candidate := result.OwnedCandidates[0]
	require.Len(t, candidate.Attributes, 1,
		"only the requested element is disclosed; age_over_18 stays withheld")

	attr := candidate.Attributes[0]
	require.Equal(t, []any{avDocType, "age_over_39"}, attr.ClaimPath)
	require.NotNil(t, attr.Value)
	require.NotNil(t, attr.Value.Bool)
	require.True(t, *attr.Value.Bool)
	require.NotNil(t, attr.DisplayName,
		"the issuer published a name for this threshold, so it must be used")
	require.Equal(t, "Over 39", *attr.DisplayName)
}

// storeIssuedAvMdoc issues a real mso_mdoc age credential under a freshly
// generated IACA/document-signer hierarchy and stores it the way issuance does.
//
// The credential is genuinely signed rather than faked: stdmdoc.NewIssuer builds
// the same two-tier PKI the AV Blueprint expects, so the stored bytes are a
// credential a verifier could actually check.
//
// Any decorate functions run on the batch just before it is stored, so a subtest
// can attach the display metadata issuance would have received from the issuer's
// credential configuration.
func storeIssuedAvMdoc(t *testing.T, eudiStorage storage.Storage, decorate ...func(*models.CredentialBatch)) {
	t.Helper()

	storeIssuedAvMdocWithElements(t, eudiStorage, map[string]any{"age_over_18": true}, decorate...)
}

// storeIssuedAvMdocWithElements is storeIssuedAvMdoc over an arbitrary element
// set, for the subtests about thresholds other than the mandatory one. The AV
// profile leaves every age_over_NN but 18 to the issuer, so a fixture that can
// only carry 18 cannot show what the wallet does with the rest.
func storeIssuedAvMdocWithElements(
	t *testing.T,
	eudiStorage storage.Storage,
	elements map[string]any,
	decorate ...func(*models.CredentialBatch),
) {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issued, err := issuer.Issue(avDocType, avDocType, elements, &holderKey.PublicKey)
	require.NoError(t, err)

	rawCredential, err := cbor.Marshal(issued)
	require.NoError(t, err)

	// The namespace -> elementIdentifier -> value shape mdoc_dcql reads, which is
	// what the mso_mdoc format parser caches at issuance.
	resolvedClaims, err := json.Marshal(map[string]map[string]any{
		avDocType: elements,
	})
	require.NoError(t, err)

	now := time.Now()
	batch := &models.CredentialBatch{
		IssuerIdentifier:           "https://av-issuer.example.com",
		CredentialIssuerIdentifier: "https://av-issuer.example.com",
		VerifiableCredentialType:   avDocType,
		Format:                     models.CredentialFormatMsoMdoc,
		Hash:                       "av-test-batch-hash",
		ProcessedSdJwtPayload:      datatypes.JSON(resolvedClaims),
		IssuedAt:                   datatypes.NullTime{V: now.Add(-time.Hour), Valid: true},
		ExpiresAt:                  datatypes.NullTime{V: now.Add(24 * time.Hour), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		Instances: []models.IssuedCredentialInstance{
			{RawCredential: rawCredential},
		},
	}

	for _, d := range decorate {
		d(batch)
	}

	require.NoError(t, db.NewCredentialStore(eudiStorage.Db()).StoreBatch(batch))
}

// withAvDisplayMetadata attaches the display metadata an AV issuer publishes for
// this credential. English only: the AV profile fixes the credential
// configuration id ("proof_of_age") and the docType, but says nothing about
// display metadata or locales, so a second language here would be inventing a
// requirement the profile does not make.
//
// The claim path is stored as ["eu.europa.ec.av.1", "age_over_18"] rather than
// ["age_over_18"], because for mso_mdoc a claim path is always
// [namespace, elementIdentifier] -- and the namespace only happens to equal the
// docType in this profile; they are different things that coincide. Nothing on the
// credential configuration records the docType itself, so this path is what ties
// the metadata to the credential.
// withAvBareClaimPathMetadata is withAvDisplayMetadata with the claim path an
// issuer publishes when it omits the namespace, which is the only difference
// between the two.
func withAvBareClaimPathMetadata(batch *models.CredentialBatch) {
	withAvDisplayMetadata(batch)
	batch.CredentialMetadata.Claims[0].Path = datatypes.JSON(`["age_over_18"]`)
}

// withAvDisplayMetadataInTwoLocales publishes every displayed string in both
// English and Dutch: the credential name, the claim label, and the issuer name.
//
// Synthetic on purpose, and it has to be. The EUDI reference issuer advertises
// exactly one locale — every one of the 577 display entries in its metadata is
// `en` — so an integration test against that container has no second translation
// to resolve and cannot prove translation at all. Proving it needs metadata a
// test controls.
func withAvDisplayMetadataInTwoLocales(batch *models.CredentialBatch) {
	batch.IssuerDisplay = []models.IssuerMetadataDisplay{
		{Name: "Yivi Age Issuer", Locale: datatypes.NullString{V: "en", Valid: true}},
		{Name: "Yivi Leeftijdsuitgever", Locale: datatypes.NullString{V: "nl", Valid: true}},
	}
	batch.CredentialMetadata = &models.CredentialMetadata{
		Display: []models.CredentialDisplay{
			{Name: "Proof of Age", Locale: datatypes.NullString{V: "en", Valid: true}},
			{Name: "Leeftijdsbewijs", Locale: datatypes.NullString{V: "nl", Valid: true}},
		},
		Claims: []models.CredentialClaim{
			{
				Path: datatypes.JSON(`["` + avDocType + `", "age_over_18"]`),
				Display: []models.ClaimDisplay{
					{Name: "Over 18", Locale: datatypes.NullString{V: "en", Valid: true}},
					{Name: "Ouder dan 18", Locale: datatypes.NullString{V: "nl", Valid: true}},
				},
			},
		},
	}
}

func withAvDisplayMetadata(batch *models.CredentialBatch) {
	batch.IssuerDisplay = []models.IssuerMetadataDisplay{
		{Name: "Yivi Age Issuer", Locale: datatypes.NullString{V: "en", Valid: true}},
	}
	batch.CredentialMetadata = &models.CredentialMetadata{
		Display: []models.CredentialDisplay{
			{Name: "Proof of Age", Locale: datatypes.NullString{V: "en", Valid: true}},
		},
		Claims: []models.CredentialClaim{
			{
				Path: datatypes.JSON(`["` + avDocType + `", "age_over_18"]`),
				Display: []models.ClaimDisplay{
					{Name: "Over 18", Locale: datatypes.NullString{V: "en", Valid: true}},
				},
			},
		},
	}
}

// newTestEudiStorage opens an in-memory eudi storage with the holder schema
// migrated, so the credential store and the DCQL handler run against the real
// storage layer rather than a stub.
// newAvMdocHandler builds the handler the way client.New does, device key binder
// included: these tests are the closest thing the package has to the real wiring,
// so a handler assembled differently here would stop being evidence about it.
func newAvMdocHandler(t *testing.T, eudiStorage storage.Storage) *mdoc_dcql.MdocDcqlHandler {
	t.Helper()

	return newAvMdocHandlerForLocale(t, eudiStorage, "en")
}

// newAvMdocHandlerForLocale is newAvMdocHandler with the wallet's UI locale
// under the test's control, which is what the per-locale display assertions need.
func newAvMdocHandlerForLocale(t *testing.T, eudiStorage storage.Storage, locale string) *mdoc_dcql.MdocDcqlHandler {
	t.Helper()

	return mdoc_dcql.NewMdocDcqlHandler(
		eudiStorage,
		clientmodels.NewCurrentLocale(locale),
		services.NewMdocDeviceKeyBinder(db.NewHolderBindingKeyStore(eudiStorage.Db())),
	)
}

func newTestEudiStorage(t *testing.T) storage.Storage {
	t.Helper()

	s, err := storage.NewStorageWithDialector(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("av-test-key"))},
		filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()),
	)
	require.NoError(t, err)
	return s
}
