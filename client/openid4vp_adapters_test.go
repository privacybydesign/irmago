package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// TestDisclosureChoicesSkipsAnOptionalPickOne pins how a skipped optional
// credential reaches the DCQL handlers: as nothing at all.
//
// A DCQL credential_set with `"required": false` becomes a DisclosurePickOne
// with Optional set, which the app may skip. It expresses that the way the IRMA
// path does — a choice selecting no credentials — and the conversion then
// produces no DisclosureSelection for that position, so no handler is asked to
// disclose anything and the credential is simply absent from the response.
//
// This matters because the alternative shape, a selected credential carrying no
// claim paths, is refused by mdoc_dcql.selectiveDiscloseByPaths and fails the
// whole disclosure. That refusal is correct — an mdoc has no always-disclosed
// payload, so disclosing zero elements would emit an empty `nameSpaces` map,
// which ISO/IEC 18013-5 does not permit — but it must never be what a legitimate
// skip produces. If someone later makes the conversion emit a selection for
// every pick-one regardless, this test fails rather than optional credentials
// becoming un-skippable.
func TestDisclosureChoicesSkipsAnOptionalPickOne(t *testing.T) {
	queryIds := []dcql.ChoiceQueryIds{
		{{Hash: "required-hash", QueryId: "required_pid", PathKeys: map[string]struct{}{}}},
		{{Hash: "optional-hash", QueryId: "optional_age", PathKeys: map[string]struct{}{}}},
	}
	required := clientmodels.DisclosureDisconSelection{
		Credentials: []clientmodels.SelectedCredential{{
			CredentialId:   "urn:eudi:pid:1",
			CredentialHash: "required-hash",
			AttributePaths: [][]any{{"given_name"}},
		}},
	}

	for name, choices := range map[string][]clientmodels.DisclosureDisconSelection{
		"optional choice selects nothing": {required, {Credentials: []clientmodels.SelectedCredential{}}},
		"optional choice is nil":          {required, {}},
		"optional choice omitted":         {required},
	} {
		t.Run(name, func(t *testing.T) {
			selections := disclosureChoicesToOpenID4VPSelections(choices, queryIds)

			require.Len(t, selections, 1,
				"a skipped optional pick-one must produce no selection, so no handler is asked to disclose nothing")
			require.Equal(t, "required_pid", selections[0].QueryId)
			require.Equal(t, "required-hash", selections[0].CredentialHash)
			require.NotEmpty(t, selections[0].ClaimPaths,
				"the required credential must still carry the paths it discloses")
		})
	}
}
