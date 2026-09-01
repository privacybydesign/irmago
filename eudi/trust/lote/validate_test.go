package lote

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// The embedded schema is the compliance target, so a build in which it fails to
// compile is a build whose conformance claims mean nothing.
func TestSchema_Compiles(t *testing.T) {
	_, err := compiledSchema()
	require.NoError(t, err)
}

// The committed golden document is the one nothing here marshalled, so validating
// it checks the published shape rather than the serialiser's opinion of it.
func TestValidate_TheGoldenDocumentConforms(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(goldenDir(t), "list.json"))
	require.NoError(t, err)
	require.NoError(t, ValidateDocument(raw))
}

// Every fixture in the suite comes out of these builders, so a non-conformant one
// would mean the whole repo asserts against a shape no publisher could produce.
func TestValidate_TheTestBuildersProduceConformantDocuments(t *testing.T) {
	signer := NewTestLoteSigner(t)
	party := signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000001")

	list := NewTestList("NL:Yivi Test", 7,
		NewTestEntity("Example Municipality", "VATNL-000000001",
			NewTestCertificateService(trust.RoleVerifier, party, "onboarded-by-yivi"),
			NewTestSkiService(trust.RoleIssuer, party),
		),
		NewTestEntity("DID Only Ltd", "",
			NewTestDidService(trust.RoleIssuer, "did:web:issuer.example.com"),
		),
	)
	require.NoError(t, ValidateList(list))
}

// An empty list is a legitimate first publication: a scheme with nobody onboarded
// yet still has to publish something the wallet accepts.
func TestValidate_AnEmptyListConforms(t *testing.T) {
	require.NoError(t, ValidateList(NewTestList("NL:Yivi Test", 1)))
}

// The signed payload and the validated document must be the same bytes, or
// validation is checking something other than what gets published.
func TestValidate_WhatIsSignedIsWhatIsValidated(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList("NL:Yivi Test", 1,
		NewTestEntity("Example Ltd", "", NewTestDidService(trust.RoleIssuer, "did:web:issuer.example.com")))

	verified, err := VerifySigned(signer.SignList(t, list), signer.X509VerificationContext())
	require.NoError(t, err)

	raw, err := json.Marshal(Document{LoTE: *verified})
	require.NoError(t, err)
	require.NoError(t, ValidateDocument(raw))
}

// ----------------------------------------------------------------------------
// The schema must actually reject things
// ----------------------------------------------------------------------------

// A validator that accepts everything is worse than none. Each of these is a
// mistake a hand-written publisher in another language could plausibly make.

func TestValidate_RejectsAnUnwrappedList(t *testing.T) {
	list := NewTestList("NL:Yivi Test", 1)
	raw, err := json.Marshal(list) // no {"LoTE": ...} wrapper
	require.NoError(t, err)
	require.ErrorContains(t, ValidateDocument(raw), "Annex A")
}

func TestValidate_RejectsALanguageMapInsteadOfASequence(t *testing.T) {
	raw := mutateGolden(t, func(scheme map[string]any, _ []any) {
		// A map where the binding requires [{lang,value}].
		scheme["SchemeName"] = map[string]any{"en": "NL:Yivi Test"}
	})
	require.ErrorContains(t, ValidateDocument(raw), "Annex A")
}

func TestValidate_RejectsAMissingMandatorySchemeField(t *testing.T) {
	raw := mutateGolden(t, func(scheme map[string]any, _ []any) {
		delete(scheme, "SchemeOperatorName")
	})
	require.ErrorContains(t, ValidateDocument(raw), "Annex A")
}

func TestValidate_RejectsAnEntityWithoutTheMandatoryAddress(t *testing.T) {
	raw := mutateGolden(t, func(_ map[string]any, entities []any) {
		information := entities[0].(map[string]any)["TrustedEntityInformation"].(map[string]any)
		delete(information, "TEAddress")
	})
	require.ErrorContains(t, ValidateDocument(raw), "Annex A")
}

func TestValidate_RejectsASingularIdentityWhereTheBindingWantsASequence(t *testing.T) {
	raw := mutateGolden(t, func(_ map[string]any, entities []any) {
		services := entities[0].(map[string]any)["TrustedEntityServices"].([]any)
		information := services[0].(map[string]any)["ServiceInformation"].(map[string]any)
		// A scalar where the binding requires an array.
		information["ServiceDigitalIdentity"] = map[string]any{"X509SKIs": "AAAA"}
	})
	require.ErrorContains(t, ValidateDocument(raw), "Annex A")
}

func TestValidate_RejectsAnUnknownMemberBesideLoTE(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(goldenDir(t), "list.json"))
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))
	document["Signature"] = "not-here-either"

	mutated, err := json.Marshal(document)
	require.NoError(t, err)
	require.ErrorContains(t, ValidateDocument(mutated), "Annex A")
}

// mutateGolden reads the committed document, hands the scheme information and the
// entity list to edit, and returns the result — so each negative test breaks
// exactly one thing about an otherwise conformant document.
func mutateGolden(t *testing.T, edit func(scheme map[string]any, entities []any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir(t), "list.json"))
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))
	lote := document["LoTE"].(map[string]any)
	edit(lote["ListAndSchemeInformation"].(map[string]any), lote["TrustedEntitiesList"].([]any))

	mutated, err := json.Marshal(document)
	require.NoError(t, err)
	return mutated
}
