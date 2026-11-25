package client

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registryTestConfiguration() *irma.Configuration {
	scheme := func(id string, demo bool) *irma.SchemeManager {
		return &irma.SchemeManager{ID: id, Demo: demo}
	}
	displayIndex := 0
	email := &irma.CredentialType{
		ID:              "email",
		SchemeManagerID: "pbdf",
		IssuerID:        "sidn-pbdf",
		Name:            irma.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
		AttributeTypes: []*irma.AttributeType{
			{ID: "domain", Name: irma.TranslatedString{"en": "Domain", "nl": "Domein"}},
			{ID: "email", Name: irma.TranslatedString{"en": "Email", "nl": "E-mail"}, DisplayIndex: &displayIndex},
			{ID: "nameless"},
			{RevocationAttribute: true},
		},
	}
	revocationOnly := &irma.CredentialType{
		ID:              "empty",
		SchemeManagerID: "pbdf",
		IssuerID:        "sidn-pbdf",
		Name:            irma.TranslatedString{"en": "Empty"},
		AttributeTypes:  []*irma.AttributeType{{RevocationAttribute: true}},
	}
	orphan := &irma.CredentialType{
		ID:              "orphan",
		SchemeManagerID: "pbdf",
		IssuerID:        "gone",
		Name:            irma.TranslatedString{"en": "Orphan"},
		AttributeTypes:  []*irma.AttributeType{{ID: "a", Name: irma.TranslatedString{"en": "A"}}},
	}
	demo := &irma.CredentialType{
		ID:              "studentCard",
		SchemeManagerID: "irma-demo",
		IssuerID:        "RU",
		Name:            irma.TranslatedString{"en": "Demo Student Card"},
		AttributeTypes:  []*irma.AttributeType{{ID: "level", Name: irma.TranslatedString{"en": "Level"}}},
	}

	return &irma.Configuration{
		SchemeManagers: map[irma.SchemeManagerIdentifier]*irma.SchemeManager{
			irma.NewSchemeManagerIdentifier("pbdf"):      scheme("pbdf", false),
			irma.NewSchemeManagerIdentifier("irma-demo"): scheme("irma-demo", true),
		},
		Issuers: map[irma.IssuerIdentifier]*irma.Issuer{
			irma.NewIssuerIdentifier("pbdf.sidn-pbdf"): {
				ID:              "sidn-pbdf",
				SchemeManagerID: "pbdf",
				Name:            irma.TranslatedString{"en": "SIDN", "nl": "SIDN NL"},
			},
			irma.NewIssuerIdentifier("irma-demo.RU"): {
				ID:              "RU",
				SchemeManagerID: "irma-demo",
				Name:            irma.TranslatedString{"en": "Demo Radboud"},
			},
		},
		CredentialTypes: map[irma.CredentialTypeIdentifier]*irma.CredentialType{
			email.Identifier():          email,
			revocationOnly.Identifier(): revocationOnly,
			orphan.Identifier():         orphan,
			demo.Identifier():           demo,
		},
	}
}

func registryEntryById(t *testing.T, entries []*clientmodels.DigitalCredentialsRegistryEntry, id string) *clientmodels.DigitalCredentialsRegistryEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.Id == id {
			return entry
		}
	}
	require.Failf(t, "entry not found", "no entry with id %q", id)
	return nil
}

func registryEntryIds(entries []*clientmodels.DigitalCredentialsRegistryEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.Id)
	}
	return ids
}

// A scheme credential type is registered as the dc+sd-jwt a request asks for:
// its identifier as vct, its attributes as claims in display order, named in
// the locale.
func TestSchemeDigitalCredentialsRegistryEntries_CredentialType(t *testing.T) {
	entries := schemeDigitalCredentialsRegistryEntries(registryTestConfiguration(), "nl", false)

	entry := registryEntryById(t, entries, "dc+sd-jwt:pbdf.sidn-pbdf.email")
	assert.Equal(t, clientmodels.Format_SdJwtVc, entry.Format)
	assert.Equal(t, "pbdf.sidn-pbdf.email", entry.Type)
	assert.Equal(t, "E-mailadres", entry.Name)
	assert.Equal(t, "SIDN NL", entry.IssuerName)
	assert.Nil(t, entry.LogoPath, "a type without a logo file has no logo path")
	assert.Nil(t, entry.Logo)
	assert.Equal(t, []clientmodels.DigitalCredentialsRegistryClaim{
		// The attribute with a display index comes first.
		{Path: []string{"email"}, Name: "E-mail"},
		{Path: []string{"domain"}, Name: "Domein"},
		// An attribute without a name is still one a request can ask for.
		{Path: []string{"nameless"}, Name: "nameless"},
	}, entry.Claims)
}

// A type with nothing to disclose is left out, a type whose issuer is unknown
// is kept without an issuer name, and demo schemes only show in developer mode.
func TestSchemeDigitalCredentialsRegistryEntries_Selection(t *testing.T) {
	conf := registryTestConfiguration()

	entries := schemeDigitalCredentialsRegistryEntries(conf, "en", false)
	assert.ElementsMatch(t, []string{
		"dc+sd-jwt:pbdf.sidn-pbdf.email",
		"dc+sd-jwt:pbdf.gone.orphan",
	}, registryEntryIds(entries))
	assert.Equal(t, "", registryEntryById(t, entries, "dc+sd-jwt:pbdf.gone.orphan").IssuerName)

	withDemo := schemeDigitalCredentialsRegistryEntries(conf, "en", true)
	assert.ElementsMatch(t, []string{
		"dc+sd-jwt:pbdf.sidn-pbdf.email",
		"dc+sd-jwt:pbdf.gone.orphan",
		"dc+sd-jwt:irma-demo.RU.studentCard",
	}, registryEntryIds(withDemo))
}

func registryTestAttribute(name string, path ...any) clientmodels.Attribute {
	attribute := clientmodels.Attribute{ClaimPath: path}
	if name != "" {
		attribute.DisplayName = &name
	}
	value := "secret"
	attribute.Value = &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &value}
	return attribute
}

// A stored SD-JWT VC is registered under its vct, with nested claims by their
// path and the rows of an array as the array itself.
func TestHeldDigitalCredentialsRegistryEntries_SdJwtVc(t *testing.T) {
	logo := &clientmodels.Image{Base64: "bG9nbw=="}
	entries := heldDigitalCredentialsRegistryEntries([]*clientmodels.Credential{{
		CredentialId:          "https://example.com/vct/diploma",
		Name:                  "Diploma",
		Issuer:                clientmodels.TrustedParty{Name: "University"},
		Image:                 logo,
		CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVc: "hash"},
		Attributes: []clientmodels.Attribute{
			registryTestAttribute("Given name", "given_name"),
			registryTestAttribute("Address", "address"),
			registryTestAttribute("Street", "address", "street"),
			registryTestAttribute("Courses", "courses"),
			registryTestAttribute("", "courses", 0),
			registryTestAttribute("Course name", "courses", 1, "name"),
			registryTestAttribute("First nationality", "nationalities", 0),
			registryTestAttribute("", "undisplayed"),
		},
	}})

	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "dc+sd-jwt:https://example.com/vct/diploma", entry.Id)
	assert.Equal(t, clientmodels.Format_SdJwtVc, entry.Format)
	assert.Equal(t, "https://example.com/vct/diploma", entry.Type)
	assert.Equal(t, "Diploma", entry.Name)
	assert.Equal(t, "University", entry.IssuerName)
	assert.Same(t, logo, entry.Logo)
	assert.Nil(t, entry.LogoPath)
	assert.Equal(t, []clientmodels.DigitalCredentialsRegistryClaim{
		{Path: []string{"given_name"}, Name: "Given name"},
		{Path: []string{"address"}, Name: "Address"},
		{Path: []string{"address", "street"}, Name: "Street"},
		{Path: []string{"courses"}, Name: "Courses"},
		// Only known through one of its elements: not named after the element.
		{Path: []string{"nationalities"}, Name: "nationalities"},
		{Path: []string{"undisplayed"}, Name: "undisplayed"},
	}, entry.Claims)
}

// An mso_mdoc is registered under its docType with its elements as claims: the
// namespace and the element identifier, whatever the element's value holds.
func TestHeldDigitalCredentialsRegistryEntries_Mdoc(t *testing.T) {
	const namespace = "org.iso.18013.5.1"
	entries := heldDigitalCredentialsRegistryEntries([]*clientmodels.Credential{{
		CredentialId:          "org.iso.18013.5.1.mDL",
		Name:                  "Driving licence",
		Issuer:                clientmodels.TrustedParty{Name: "RDW"},
		CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_MsoMdoc: "hash"},
		Attributes: []clientmodels.Attribute{
			registryTestAttribute("Namespace header", namespace),
			registryTestAttribute("Family name", namespace, "family_name"),
			registryTestAttribute("Code", namespace, "driving_privileges", 0, "vehicle_category_code"),
			registryTestAttribute("Place", namespace, "birth_place", "locality"),
			registryTestAttribute("Privileges", namespace, "driving_privileges"),
		},
	}})

	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "mso_mdoc:org.iso.18013.5.1.mDL", entry.Id)
	assert.Equal(t, clientmodels.Format_MsoMdoc, entry.Format)
	assert.Equal(t, "org.iso.18013.5.1.mDL", entry.Type)
	assert.Equal(t, []clientmodels.DigitalCredentialsRegistryClaim{
		{Path: []string{namespace, "family_name"}, Name: "Family name"},
		{Path: []string{namespace, "driving_privileges"}, Name: "driving_privileges"},
		{Path: []string{namespace, "birth_place"}, Name: "birth_place"},
	}, entry.Claims)
}

// Credentials of one type and format share an entry that offers the claims of
// all of them. The same type in another format is an entry of its own.
func TestHeldDigitalCredentialsRegistryEntries_MergesPerFormatAndType(t *testing.T) {
	credential := func(format clientmodels.CredentialFormat, name string, attributes ...clientmodels.Attribute) *clientmodels.Credential {
		return &clientmodels.Credential{
			CredentialId:          "urn:example:pid",
			Name:                  name,
			CredentialInstanceIds: map[clientmodels.CredentialFormat]string{format: "hash-" + name},
			Attributes:            attributes,
		}
	}

	entries := heldDigitalCredentialsRegistryEntries([]*clientmodels.Credential{
		credential(clientmodels.Format_SdJwtVc, "First", registryTestAttribute("A", "a"), registryTestAttribute("B", "b")),
		credential(clientmodels.Format_SdJwtVc, "Second", registryTestAttribute("B again", "b"), registryTestAttribute("C", "c")),
		credential(clientmodels.Format_SdJwtVcdm, "Vcdm", registryTestAttribute("A", "credentialSubject", "a")),
		// Nothing a request could match on.
		credential(clientmodels.Format_SdJwtVc, "Empty"),
		{Name: "No type", CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVc: "x"}},
		nil,
	})

	require.Equal(t, []string{"dc+sd-jwt:urn:example:pid", "vc+sd-jwt:urn:example:pid"}, registryEntryIds(entries))
	assert.Equal(t, "First", entries[0].Name)
	assert.Equal(t, []clientmodels.DigitalCredentialsRegistryClaim{
		{Path: []string{"a"}, Name: "A"},
		{Path: []string{"b"}, Name: "B"},
		{Path: []string{"c"}, Name: "C"},
	}, entries[0].Claims)
	assert.Equal(t, clientmodels.Format_SdJwtVcdm, entries[1].Format)
}

// What is registered is stored by the platform, outside the wallet: no
// attribute value may travel along.
func TestHeldDigitalCredentialsRegistryEntries_CarryNoValues(t *testing.T) {
	entries := heldDigitalCredentialsRegistryEntries([]*clientmodels.Credential{{
		CredentialId:          "urn:example:pid",
		Name:                  "PID",
		CredentialInstanceIds: map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVc: "hash"},
		Attributes:            []clientmodels.Attribute{registryTestAttribute("Given name", "given_name")},
	}})

	encoded, err := json.Marshal(entries)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "secret")
	assert.JSONEq(t, `[{
		"id": "dc+sd-jwt:urn:example:pid",
		"format": "dc+sd-jwt",
		"type": "urn:example:pid",
		"name": "PID",
		"issuer_name": "",
		"claims": [{"path": ["given_name"], "name": "Given name"}]
	}]`, string(encoded))
}

func TestSortDigitalCredentialsRegistryEntries(t *testing.T) {
	entries := []*clientmodels.DigitalCredentialsRegistryEntry{{Id: "mso_mdoc:b"}, {Id: "dc+sd-jwt:z"}, {Id: "dc+sd-jwt:a"}}
	sortDigitalCredentialsRegistryEntries(entries)
	assert.Equal(t, []string{"dc+sd-jwt:a", "dc+sd-jwt:z", "mso_mdoc:b"}, registryEntryIds(entries))
}
