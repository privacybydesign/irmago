package client

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

func (client *Client) GetCredentialStore() ([]*clientmodels.CredentialStoreItem, error) {
	irmaConfig := client.irmaClient.Configuration
	result := []*clientmodels.CredentialStoreItem{}

	for _, cred := range irmaConfig.CredentialTypes {
		if !cred.IsInCredentialStore {
			continue
		}

		issuerId := cred.IssuerIdentifier()
		issuer, ok := irmaConfig.Issuers[issuerId]

		if !ok {
			return nil, fmt.Errorf("failed to get issuer info for %s", issuerId.String())
		}

		if cred.IssueURL == nil {
			return nil, fmt.Errorf("encountered credential store item without issue url: %s", issuerId.String())
		}

		attributes := []clientmodels.Attribute{}

		for _, attr := range sortedAttributeTypes(cred.AttributeTypes) {
			if attr.RevocationAttribute {
				continue
			}
			attributes = append(attributes, clientmodels.Attribute{
				Id:          attr.ID,
				DisplayName: clientmodels.TranslatedString(attr.Name),
				Value: &clientmodels.AttributeValue{
					Type: displayHintToAttributeType(attr.DisplayHint),
				},
			})
		}

		result = append(result, &clientmodels.CredentialStoreItem{
			Credential: clientmodels.CredentialDescriptor{
				CredentialId: cred.Identifier().String(),
				Name:         clientmodels.TranslatedString(cred.Name),
				Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
				IssueURL:     convertOptionalTranslatedString(cred.IssueURL),
				Category:     convertOptionalTranslatedString(cred.Category),
				ImagePath:    optionalString(cred.Logo(irmaConfig)),
				Attributes:   attributes,
			},
			Faq: clientmodels.Faq{
				Intro:   convertOptionalTranslatedString(cred.FAQIntro),
				Purpose: convertOptionalTranslatedString(cred.FAQPurpose),
				Content: convertOptionalTranslatedString(cred.FAQContent),
				HowTo:   convertOptionalTranslatedString(cred.FAQHowto),
			},
		})
	}

	return result, nil
}

func convertOptionalTranslatedString(s *irma.TranslatedString) *clientmodels.TranslatedString {
	if s == nil {
		return nil
	}
	t := clientmodels.TranslatedString(*s)
	return &t
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// buildIssuerTrustedParty constructs a TrustedParty for an issuer, including its logo
// and the scheme manager as parent.
func buildIssuerTrustedParty(irmaConfig *irma.Configuration, issuer *irma.Issuer) clientmodels.TrustedParty {
	scheme := irmaConfig.SchemeManagers[issuer.SchemeManagerIdentifier()]
	parent := clientmodels.TrustedParty{
		Id:       scheme.Identifier().String(),
		Name:     clientmodels.TranslatedString(scheme.Name),
		Verified: scheme.Status == irma.SchemeManagerStatusValid,
	}
	return clientmodels.TrustedParty{
		Id:        issuer.Identifier().String(),
		Name:      clientmodels.TranslatedString(issuer.Name),
		ImagePath: optionalString(issuer.Logo(irmaConfig)),
		Verified:  scheme.Status == irma.SchemeManagerStatusValid,
		Parent:    &parent,
	}
}

// creates a credential descriptor containing only the attributes specified
func createCredentialDescriptor(
	irmaConfig *irma.Configuration,
	attrs []*irmaclient.DisclosureCandidate,
) (*clientmodels.CredentialDescriptor, error) {
	id := attrs[0].Type.CredentialTypeIdentifier()
	info, ok := irmaConfig.CredentialTypes[id]

	if !ok {
		return nil, fmt.Errorf("failed to find credential info for %s", id.String())
	}

	issuerId := info.IssuerIdentifier()
	issuer := irmaConfig.Issuers[issuerId]
	attributes := []clientmodels.Attribute{}

	// only put the requested attributes in the descriptor
	for _, at := range attrs {
		for _, a := range info.AttributeTypes {
			if a.GetAttributeTypeIdentifier() == at.Type {
				requestedValue := &clientmodels.AttributeValue{
					Type: clientmodels.AttributeType_String,
				}
				if at.Value != nil {
					s := at.Value["en"]
					if s == "" {
						s = at.Value[""]
					}
					requestedValue.String = &s
				}
				attributes = append(attributes, clientmodels.Attribute{
					Id:             a.ID,
					DisplayName:    clientmodels.TranslatedString(a.Name),
					RequestedValue: requestedValue,
				})
			}
		}
	}

	return &clientmodels.CredentialDescriptor{
		CredentialId: info.Identifier().String(),
		Name:         clientmodels.TranslatedString(info.Name),
		Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
		Category:     convertOptionalTranslatedString(info.Category),
		ImagePath:    optionalString(info.Logo(irmaConfig)),
		Attributes:   attributes,
		IssueURL:     convertOptionalTranslatedString(info.IssueURL),
	}, nil
}

func getCredentialDescriptor(irmaConfig *irma.Configuration, id irma.CredentialTypeIdentifier) (*clientmodels.CredentialDescriptor, error) {
	info, ok := irmaConfig.CredentialTypes[id]

	if !ok {
		return nil, fmt.Errorf("failed to find credential info for %s", id.String())
	}

	issuerId := info.IssuerIdentifier()
	issuer := irmaConfig.Issuers[issuerId]
	attributes := []clientmodels.Attribute{}

	for _, at := range sortedAttributeTypes(info.AttributeTypes) {
		if at.RevocationAttribute {
			continue
		}
		attributes = append(attributes, clientmodels.Attribute{
			Id:          at.ID,
			DisplayName: clientmodels.TranslatedString(at.Name),
			Value: &clientmodels.AttributeValue{
				Type: clientmodels.AttributeType_String,
			},
		})
	}

	return &clientmodels.CredentialDescriptor{
		CredentialId: info.Identifier().String(),
		Name:         clientmodels.TranslatedString(info.Name),
		Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
		Category:     convertOptionalTranslatedString(info.Category),
		ImagePath:    optionalString(info.Logo(irmaConfig)),
		Attributes:   attributes,
		IssueURL:     convertOptionalTranslatedString(info.IssueURL),
	}, nil
}

func credentialInfoListToSchemaless(irmaConfig *irma.Configuration, creds irma.CredentialInfoList) ([]*clientmodels.Credential, error) {
	result := []*clientmodels.Credential{}
	intermediateResult := map[string]*clientmodels.Credential{}

	// loop over all credentials and immediately combine them when they're the same
	// attributes + credential ID in different credential formats
	for _, cred := range creds {
		instanceHash, err := hashAttributesAndCredType(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to hash attributes and cred type: %w", err)
		}

		format := clientmodels.CredentialFormat(cred.CredentialFormat)

		// if there's an existing instance we just add some format specific info
		// and combine the two formats into a single credential result
		if existing, ok := intermediateResult[instanceHash]; ok {
			existing.BatchInstanceCountsRemaining[format] = cred.InstanceCount
			existing.CredentialInstanceIds[format] = cred.Hash
			existing.Revoked = existing.Revoked || cred.Revoked
			existing.RevocationSupported = existing.RevocationSupported || cred.RevocationSupported
		} else
		// if there's no existing one we create a new one
		{
			id := cred.Identifier()
			info, ok := irmaConfig.CredentialTypes[id]

			if !ok {
				return nil, fmt.Errorf("failed to find credential info for %s", id.String())
			}

			issuerId := info.IssuerIdentifier()
			issuer := irmaConfig.Issuers[issuerId]
			attributes := []clientmodels.Attribute{}

			for _, at := range sortedAttributeTypes(info.AttributeTypes) {
				if at.RevocationAttribute {
					continue
				}
				attrValue := cred.Attributes[at.GetAttributeTypeIdentifier()]
				description := clientmodels.TranslatedString(at.Description)
				if at.IsOptional() && len(attrValue) == 0 {
					continue
				}
				attributes = append(attributes, clientmodels.Attribute{
					Id:          at.ID,
					DisplayName: clientmodels.TranslatedString(at.Name),
					Description: &description,
					Value:       buildAttributeValue(at.DisplayHint, &attrValue),
				})
			}

			logo := info.Logo(irmaConfig)

			newCred := clientmodels.Credential{
				CredentialId: cred.Identifier().String(),
				Hash:         instanceHash,
				ImagePath:    &logo,
				Name:         clientmodels.TranslatedString(info.Name),
				Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
				CredentialInstanceIds: map[clientmodels.CredentialFormat]string{
					format: cred.Hash,
				},
				BatchInstanceCountsRemaining: map[clientmodels.CredentialFormat]*uint{
					format: cred.InstanceCount,
				},
				Attributes:          attributes,
				IssuanceDate:        time.Time(cred.SignedOn).Unix(),
				ExpiryDate:          time.Time(cred.Expires).Unix(),
				Revoked:             cred.Revoked,
				RevocationSupported: cred.RevocationSupported,
				IssueURL:            convertOptionalTranslatedString(info.IssueURL),
			}
			intermediateResult[instanceHash] = &newCred
		}
	}

	for _, credential := range intermediateResult {
		result = append(result, credential)
	}

	return result, nil
}

func (client *Client) GetCredentials() ([]*clientmodels.Credential, error) {
	// Get IRMA + SDJWT-over-IRMA credentials, filter out keyshare credentials
	creds := client.getIrmaCredentialInfoList()
	creds = filterOutKeyshareCredentials(client.irmaClient.Configuration, creds)

	irmaCreds, err := credentialInfoListToSchemaless(client.irmaClient.Configuration, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to convert IRMA credentials to schemaless format: %v", err)
	}

	// Get EUDI credentials and convert to the same format, then combine with IRMA credentials.
	credentialService := services.NewCredentialService(client.eudiStorage)
	oidCreds, err := credentialService.GetCredentialMetadataList()
	if err != nil {
		return nil, fmt.Errorf("failed to get OID4VCI credentials from storage: %v", err)
	}

	return append(irmaCreds, oidCreds...), nil
}

// filterOutKeyshareCredentials removes credentials that are used for keyshare server enrollment.
func filterOutKeyshareCredentials(conf *irma.Configuration, creds irma.CredentialInfoList) irma.CredentialInfoList {
	keyshareCredTypes := make(map[irma.CredentialTypeIdentifier]struct{})
	for _, scheme := range conf.SchemeManagers {
		if scheme.KeyshareAttribute != "" {
			credType := irma.NewAttributeTypeIdentifier(scheme.KeyshareAttribute).CredentialTypeIdentifier()
			keyshareCredTypes[credType] = struct{}{}
		}
	}

	filtered := make(irma.CredentialInfoList, 0, len(creds))
	for _, cred := range creds {
		if _, isKeyshare := keyshareCredTypes[cred.Identifier()]; !isKeyshare {
			filtered = append(filtered, cred)
		}
	}
	return filtered
}

func displayHintToAttributeType(s string) clientmodels.AttributeType {
	result := clientmodels.AttributeType_String
	switch s {
	case "portraitPhoto":
		result = clientmodels.AttributeType_Base64Image
	}
	return result
}

// buildAttributeValue creates an AttributeValue with the value in the correct field
// based on the attribute's display hint.
func buildAttributeValue(displayHint string, rawValue *irma.TranslatedString) *clientmodels.AttributeValue {
	attrType := displayHintToAttributeType(displayHint)
	val := &clientmodels.AttributeValue{Type: attrType}
	if rawValue == nil {
		return val
	}
	switch attrType {
	case clientmodels.AttributeType_Base64Image:
		// For base64 images, use the untranslated value
		s := (*rawValue)["en"]
		if s == "" {
			s = (*rawValue)[""]
		}
		val.Base64Image = &s
	default:
		s := (*rawValue)["en"]
		if s == "" {
			s = (*rawValue)[""]
		}
		val.String = &s
	}
	return val
}

// SatisfiesRequestedAttributes checks that `given` contains everything needed to satisfy `requested`.
// Returns ok + list of issues with paths (e.g. "address.street", "roles[2]").
func SatisfiesRequestedAttributes(given, requested []clientmodels.Attribute) (bool, []string) {
	var issues []string
	checkAttributeList(&issues, "", given, requested)
	return len(issues) == 0, issues
}

func checkAttributeList(issues *[]string, path string, given, requested []clientmodels.Attribute) {
	givenByID := make(map[string]clientmodels.Attribute, len(given))
	for _, g := range given {
		givenByID[g.Id] = g
	}

	for _, r := range requested {
		p := joinPath(path, r.Id)

		g, ok := givenByID[r.Id]
		if !ok {
			*issues = append(*issues, fmt.Sprintf("missing attribute: %s", p))
			continue
		}

		// No requested constraint/value => existence is enough.
		if r.RequestedValue == nil {
			continue
		}

		// If a constraint is requested, we need a given value.
		if g.Value == nil {
			*issues = append(*issues, fmt.Sprintf("missing value for attribute: %s", p))
			continue
		}

		checkValueSatisfies(issues, p, *g.Value, *r.RequestedValue)
	}
}

func checkValueSatisfies(issues *[]string, path string, given clientmodels.AttributeValue, req clientmodels.AttributeValue) {
	// Enforce type when requested type is set.
	if req.Type != "" && given.Type != req.Type {
		*issues = append(*issues, fmt.Sprintf("type mismatch at %s: have %q want %q", path, given.Type, req.Type))
		return
	}

	switch req.Type {
	case clientmodels.AttributeType_Object:
		// Nested attributes must satisfy nested requested constraints.
		checkAttributeList(issues, path, given.Object, req.Object)

	case clientmodels.AttributeType_Array:
		checkArrayAllOfUnordered(issues, path, given.Array, req.Array)

	case clientmodels.AttributeType_Int:
		if req.Int == nil {
			return
		}
		if given.Int == nil || *given.Int != *req.Int {
			*issues = append(*issues, fmt.Sprintf("int mismatch at %s", path))
		}

	case clientmodels.AttributeType_Bool:
		if req.Bool == nil {
			return
		}
		if given.Bool == nil || *given.Bool != *req.Bool {
			*issues = append(*issues, fmt.Sprintf("bool mismatch at %s", path))
		}

	case clientmodels.AttributeType_String:
		if req.String == nil {
			return
		}
		if given.String == nil {
			*issues = append(*issues, fmt.Sprintf("string missing at %s", path))
			return
		}
		if *given.String != *req.String {
			*issues = append(*issues, fmt.Sprintf("string mismatch at %s", path))
		}

	case clientmodels.AttributeType_Image:
		if req.ImagePath == nil {
			return
		}
		if given.ImagePath == nil || *given.ImagePath != *req.ImagePath {
			*issues = append(*issues, fmt.Sprintf("image mismatch at %s", path))
		}

	case clientmodels.AttributeType_Base64Image:
		if req.Base64Image == nil {
			return
		}
		if given.Base64Image == nil || *given.Base64Image != *req.Base64Image {
			*issues = append(*issues, fmt.Sprintf("base64 image mismatch at %s", path))
		}

	default:
		// Unknown / empty requested type => treat as "presence already checked"
	}
}

// Unordered "all-of":
// Every requested element must be satisfied by some *distinct* element in given.
// Uses backtracking to avoid greedy mismatches.
func checkArrayAllOfUnordered(issues *[]string, path string, given, req []clientmodels.AttributeValue) {
	// If nothing requested, array type is enough.
	if len(req) == 0 {
		return
	}
	if len(given) < len(req) {
		*issues = append(*issues, fmt.Sprintf("array too short at %s: have %d want >= %d", path, len(given), len(req)))
		return
	}

	used := make([]bool, len(given))

	var dfs func(i int) bool
	dfs = func(i int) bool {
		if i == len(req) {
			return true
		}

		// Try to match req[i] with any unused given[j]
		for j := range given {
			if used[j] {
				continue
			}
			if valueSatisfiesNoReport(given[j], req[i]) {
				used[j] = true
				if dfs(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}

	if dfs(0) {
		return
	}

	// If it doesn't match, add a helpful (though not minimal) error.
	*issues = append(*issues, fmt.Sprintf("array mismatch at %s: could not satisfy all requested elements (unordered all-of)", path))
}

// valueSatisfiesNoReport mirrors checkValueSatisfies but returns bool only (no side-effects).
// This is used for array matching/backtracking.
func valueSatisfiesNoReport(given clientmodels.AttributeValue, req clientmodels.AttributeValue) bool {
	if req.Type != "" && given.Type != req.Type {
		return false
	}

	switch req.Type {
	case clientmodels.AttributeType_Object:
		return attributeListSatisfiesNoReport(given.Object, req.Object)

	case clientmodels.AttributeType_Array:
		// Recurse into unordered all-of arrays as well.
		return arrayAllOfUnorderedNoReport(given.Array, req.Array)

	case clientmodels.AttributeType_Int:
		if req.Int == nil {
			return true
		}
		return given.Int != nil && *given.Int == *req.Int

	case clientmodels.AttributeType_Bool:
		if req.Bool == nil {
			return true
		}
		return given.Bool != nil && *given.Bool == *req.Bool

	case clientmodels.AttributeType_String:
		if req.String == nil {
			return true
		}
		return given.String != nil && *given.String == *req.String

	case clientmodels.AttributeType_Image:
		if req.ImagePath == nil {
			return true
		}
		return given.ImagePath != nil && *given.ImagePath == *req.ImagePath

	case clientmodels.AttributeType_Base64Image:
		if req.Base64Image == nil {
			return true
		}
		return given.Base64Image != nil && *given.Base64Image == *req.Base64Image

	default:
		return true
	}
}

func arrayAllOfUnorderedNoReport(given, req []clientmodels.AttributeValue) bool {
	if len(req) == 0 {
		return true
	}
	if len(given) < len(req) {
		return false
	}

	used := make([]bool, len(given))
	var dfs func(i int) bool
	dfs = func(i int) bool {
		if i == len(req) {
			return true
		}
		for j := range given {
			if used[j] {
				continue
			}
			if valueSatisfiesNoReport(given[j], req[i]) {
				used[j] = true
				if dfs(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}
	return dfs(0)
}

func attributeListSatisfiesNoReport(given, requested []clientmodels.Attribute) bool {
	givenByID := make(map[string]clientmodels.Attribute, len(given))
	for _, g := range given {
		givenByID[g.Id] = g
	}
	for _, r := range requested {
		g, ok := givenByID[r.Id]
		if !ok {
			return false
		}
		if r.RequestedValue == nil {
			continue
		}
		if g.Value == nil {
			return false
		}
		if !valueSatisfiesNoReport(*g.Value, *r.RequestedValue) {
			return false
		}
	}
	return true
}

func joinPath(prefix, id string) string {
	if prefix == "" {
		return id
	}
	return strings.Join([]string{prefix, id}, ".")
}

// sortedAttributeTypes returns attribute types sorted by DisplayIndex.
// Attributes with a DisplayIndex come first (ordered by index), followed by
// those without (in their original schema order).
func sortedAttributeTypes(attrs []*irma.AttributeType) []*irma.AttributeType {
	sorted := make([]*irma.AttributeType, len(attrs))
	copy(sorted, attrs)
	slices.SortStableFunc(sorted, func(a, b *irma.AttributeType) int {
		aHas := a.DisplayIndex != nil
		bHas := b.DisplayIndex != nil
		if aHas && bHas {
			return *a.DisplayIndex - *b.DisplayIndex
		}
		if aHas {
			return -1
		}
		if bHas {
			return 1
		}
		return 0
	})
	return sorted
}
