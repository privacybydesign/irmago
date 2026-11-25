package sessiontest

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/irma"
)

// The Digital Credentials API registry is what the app registers with the
// platform: the platform only routes a request to the wallet when the request
// matches a registered entry. An entry that names a type or a claim differently
// than the wallet's own DCQL matching does is therefore worse than a missing
// one: the platform offers the wallet, and the wallet then finds nothing.
//
// This test builds the registry of a stored wallet that holds every format (the
// v1.5.0 snapshot: IRMA credentials, SD-JWT VCs, mso_mdocs and SD-JWT-secured
// VCDM credentials) and then asks the wallet, over the Digital Credentials API
// itself, for every claim the registry lists. Nothing here needs a server: an
// unsigned DC API request is parsed and matched inside the wallet.
func TestDigitalCredentialsRegistryOfStoredWallet(t *testing.T) {
	c, sessionHandler, _ := setupStorageRegressionClient(t, "v1.5.0")

	entries, err := c.GetDigitalCredentialsRegistry()
	require.NoError(t, err)

	// One entry per format and type, in a stable order: whoever stores the
	// registry must be able to tell that nothing changed.
	ids := registryIds(entries)
	require.True(t, slices.IsSorted(ids), "entries must be sorted by id")
	require.Len(t, slices.Compact(slices.Clone(ids)), len(ids), "entry ids must be unique")
	again, err := c.GetDigitalCredentialsRegistry()
	require.NoError(t, err)
	require.Equal(t, mustMarshal(t, entries), mustMarshal(t, again), "an unchanged wallet must give an unchanged registry")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)

	// Every credential the wallet obtained over OpenID4VCI is listed under its
	// own format and type.
	held := 0
	for _, cred := range creds {
		for format := range cred.CredentialInstanceIds {
			if format == clientmodels.Format_Idemix {
				continue
			}
			if isIrmaCredentialId(c, cred.CredentialId) {
				continue
			}
			held++
			entry := registryEntry(t, entries, format, cred.CredentialId)
			require.NotEmpty(t, entry.Claims, "entry %s must list claims", entry.Id)
			require.NotEmpty(t, entry.Name, "entry %s must have a name", entry.Id)
			require.Nil(t, entry.LogoPath, "a stored credential's logo is not a plain file")
		}
	}
	require.Positive(t, held, "the snapshot must hold OpenID4VCI credentials")
	for _, expected := range []struct {
		format clientmodels.CredentialFormat
		typ    string
	}{
		{clientmodels.Format_MsoMdoc, avDocType},
		{clientmodels.Format_MsoMdoc, pidMdocDocType},
		{clientmodels.Format_SdJwtVc, "https://localhost:8443/vct/test"},
		{clientmodels.Format_SdJwtVcdm, vcdmCredentialId},
		{clientmodels.Format_SdJwtVcdm, openBadgeCredentialId},
	} {
		registryEntry(t, entries, expected.format, expected.typ)
	}

	// An mdoc claim is always the namespace and the element identifier.
	for _, entry := range entries {
		if entry.Format != clientmodels.Format_MsoMdoc {
			continue
		}
		for _, claim := range entry.Claims {
			require.Len(t, claim.Path, 2, "mdoc claim %v of %s", claim.Path, entry.Id)
		}
	}

	// The scheme's credential types are listed whether the wallet holds them
	// or not, as the dc+sd-jwt a request for one asks for.
	email := registryEntry(t, entries, clientmodels.Format_SdJwtVc, "test.test.email")
	require.Equal(t, []clientmodels.DigitalCredentialsRegistryClaim{{Path: []string{"email"}, Name: "Email address"}}, email.Claims)
	require.Nil(t, email.Logo)
	schemeEntries := 0
	for _, entry := range entries {
		if !isIrmaCredentialId(c, entry.Type) {
			continue
		}
		schemeEntries++
		require.Equal(t, clientmodels.Format_SdJwtVc, entry.Format)
		if entry.LogoPath != nil {
			_, err := os.Stat(*entry.LogoPath)
			require.NoError(t, err, "logo path of %s must be a file", entry.Id)
		}
	}
	require.Positive(t, schemeEntries)

	// What is registered is stored by the platform, outside the wallet: no
	// attribute value may be in it.
	encoded := mustMarshal(t, entries)
	for _, cred := range creds {
		for _, value := range stringValues(cred.Attributes) {
			require.NotContains(t, encoded, fmt.Sprintf("%q", value),
				"the registry must not carry the value of a claim of %s", cred.CredentialId)
		}
	}

	// Every claim the registry lists for a credential the wallet holds can be
	// asked for over the Digital Credentials API, by the format, type and path
	// the entry names, and the wallet then finds that credential.
	sessionId := 100
	for _, entry := range entries {
		if isIrmaCredentialId(c, entry.Type) {
			continue
		}
		for _, claim := range entry.Claims {
			sessionId++
			session := startDcApiSession(t, c, sessionId, sessionHandler, &openid4vp.DcApiRequest{
				Protocol: openid4vp.DcApiProtocolUnsigned,
				Origin:   dcApiOrigin,
				Data:     unsignedDcApiRequestData(t, string(openid4vp.ResponseMode_DcApi), registryDcql(t, entry, claim), nil),
			})
			require.Equal(t, clientmodels.Status_RequestPermission, session.Status,
				"asking for %v of %s must reach the permission screen, got %+v", claim.Path, entry.Id, session.Error)
			require.NotNil(t, session.DisclosurePlan)
			require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
			owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
			require.NotEmpty(t, owned, "asking for %v of %s must find a stored credential", claim.Path, entry.Id)
			found := false
			for _, option := range owned {
				require.Equal(t, entry.Format, option.Credentials[0].Format)
				found = found || option.Credentials[0].CredentialId == entry.Type
				// A vct or a docType is what the request asked for, so nothing
				// else may answer it. A VCDM request has no type the entry
				// could name (see registryDcql), so any credential with the
				// claim answers it.
				if entry.Format != clientmodels.Format_SdJwtVcdm {
					require.Equal(t, entry.Type, option.Credentials[0].CredentialId)
				}
			}
			require.True(t, found, "asking for %v of %s must find a credential of that type", claim.Path, entry.Id)

			userInteraction(t, c, clientmodels.SessionUserInteraction{SessionId: sessionId, Type: clientmodels.UI_DismissSession})
			session = awaitSessionState(t, sessionHandler)
			require.Equal(t, clientmodels.Status_Dismissed, session.Status)
		}
	}

	// A scheme credential type the wallet does not hold is still answered: the
	// user is offered to obtain it, which is why it is registered at all.
	sessionId++
	session := startDcApiSession(t, c, sessionId, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiRequestData(t, string(openid4vp.ResponseMode_DcApi), registryDcql(t, email, email.Claims[0]), nil),
	})
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	choice := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.NotEmpty(t, append(registryOptionIds(choice), registryObtainableIds(choice)...),
		"a request for a scheme credential type must be answerable by an owned or an obtainable credential")
	userInteraction(t, c, clientmodels.SessionUserInteraction{SessionId: sessionId, Type: clientmodels.UI_DismissSession})
	require.Equal(t, clientmodels.Status_Dismissed, awaitSessionState(t, sessionHandler).Status)

	// The test schemes are demo schemes, which are only registered in
	// developer mode. The stored credentials stay.
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: false})
	withoutDemo, err := c.GetDigitalCredentialsRegistry()
	require.NoError(t, err)
	require.Len(t, withoutDemo, len(entries)-schemeEntries)
	for _, entry := range withoutDemo {
		require.False(t, isIrmaCredentialId(c, entry.Type), "demo scheme type %s must not be registered outside developer mode", entry.Id)
	}

	// Removing a stored credential takes its entry out of the registry.
	av := findMdocCredentialByDocType(t, creds, avDocType)
	require.NoError(t, c.RemoveCredentialsByHash(av.CredentialInstanceIds))
	afterRemoval, err := c.GetDigitalCredentialsRegistry()
	require.NoError(t, err)
	require.NotContains(t, registryIds(afterRemoval), string(clientmodels.Format_MsoMdoc)+":"+avDocType)
	require.Len(t, afterRemoval, len(withoutDemo)-1)
}

func registryIds(entries []*clientmodels.DigitalCredentialsRegistryEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.Id)
	}
	return ids
}

func registryEntry(
	t *testing.T,
	entries []*clientmodels.DigitalCredentialsRegistryEntry,
	format clientmodels.CredentialFormat,
	credentialType string,
) *clientmodels.DigitalCredentialsRegistryEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.Format == format && entry.Type == credentialType {
			return entry
		}
	}
	require.Failf(t, "entry not found", "no %s entry for %q among %v", format, credentialType, registryIds(entries))
	return nil
}

func isIrmaCredentialId(c *client.Client, id string) bool {
	_, ok := c.GetIrmaConfiguration().CredentialTypes[irma.NewCredentialTypeIdentifier(id)]
	return ok
}

func registryOptionIds(choice clientmodels.DisclosurePickOne) []string {
	ids := []string{}
	for _, option := range choice.OwnedOptions {
		for _, cred := range option.Credentials {
			ids = append(ids, cred.CredentialId)
		}
	}
	return ids
}

func registryObtainableIds(choice clientmodels.DisclosurePickOne) []string {
	ids := []string{}
	for _, option := range choice.ObtainableOptions {
		ids = append(ids, option.CredentialId)
	}
	return ids
}

// registryDcql is the dcql_query a verifier writes to ask for one claim of a
// registered entry, from nothing but what the entry says.
func registryDcql(
	t *testing.T,
	entry *clientmodels.DigitalCredentialsRegistryEntry,
	claim clientmodels.DigitalCredentialsRegistryClaim,
) string {
	t.Helper()
	query := map[string]any{
		"id":     "registered",
		"format": string(entry.Format),
		"claims": []any{map[string]any{"path": claim.Path}},
	}
	switch entry.Format {
	case clientmodels.Format_SdJwtVc:
		query["meta"] = map[string]any{"vct_values": []string{entry.Type}}
	case clientmodels.Format_MsoMdoc:
		query["meta"] = map[string]any{"doctype_value": entry.Type}
	case clientmodels.Format_SdJwtVcdm:
		// No type_values: the registry names a VCDM credential by its type
		// identity, which is a display key and not what a request matches on.
	default:
		require.Failf(t, "unexpected format", "%s", entry.Format)
	}
	dcql, err := json.Marshal(map[string]any{"credentials": []any{query}})
	require.NoError(t, err)
	return string(dcql)
}

func stringValues(attributes []clientmodels.Attribute) []string {
	values := []string{}
	for _, attribute := range attributes {
		// Short values ("NL", "true") are bound to occur in a claim name.
		if attribute.Value != nil && attribute.Value.String != nil && len(*attribute.Value.String) >= 8 {
			values = append(values, *attribute.Value.String)
		}
	}
	return values
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	bts, err := json.Marshal(v)
	require.NoError(t, err)
	return string(bts)
}
