package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type TranslatedString map[string]string

// CredentialFormat is a type alias for irmaclient.CredentialFormat so the two packages share the same type.
type CredentialFormat = irmaclient.CredentialFormat

type TrustedParty struct {
	Id string `json:"id"`
	// Display name for the issuer
	Name TranslatedString `json:"name"`
	// Url for the issuer (which can be different per language)
	Url *TranslatedString `json:"url"`
	// Absolute path to the image for this issuer stored on disk
	ImagePath *string `json:"image_path"`
	// The trust chain for this issuer (if any)
	Parent *TrustedParty `json:"parent"`
	// Whether this party is verified (TODO: should this be implied by the parent?)
	Verified bool `json:"verified"`
}

type AttributeType string

const (
	AttributeType_Object           AttributeType = "object"
	AttributeType_Array            AttributeType = "array"
	AttributeType_String           AttributeType = "string"
	AttributeType_TranslatedString AttributeType = "translated_string"
	AttributeType_Bool             AttributeType = "bool"
	AttributeType_Int              AttributeType = "int"
	AttributeType_Image            AttributeType = "image"
	AttributeType_Base64Image      AttributeType = "base64_image"
)

type AttributeValue struct {
	Type AttributeType `json:"type"`

	String           *string           `json:"string"`
	Int              *int64            `json:"int"`
	Bool             *bool             `json:"bool"`
	TranslatedString *TranslatedString `json:"translated_string"`
	Array            []AttributeValue  `json:"array"`
	Object           []Attribute       `json:"object"`
	ImagePath        *string           `json:"image_path"`
	Base64Image      *string           `json:"base64_image"`
}

type Attribute struct {
	// Id for this attribute (only the last part in case of irma/idemix)
	Id string `json:"id"`
	// The name for this attribute as displayed to the end user
	DisplayName TranslatedString `json:"display_name"`
	// The description for this attribute if any
	Description TranslatedString `json:"description"`
	// The value that this attribute has as provided by the issuer (absent when it's just an attribute description)
	Value *AttributeValue `json:"value"`
	// The value that was requested by a verifier (if any)
	RequestedValue *AttributeValue `json:"requested_value"`
}

type Credential struct {
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for Eudi credentials this would be in the form of `https://example.credential.com`
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Absolute path to the image for this credential stored on disk
	ImagePath string `json:"image_path"`
	// The display name for this credential
	Name TranslatedString `json:"name"`
	// All information about the credential issuer
	Issuer TrustedParty `json:"issuer"`
	// The IDs for all instances of this credential in all different formats it's available in.
	CredentialInstanceIds map[CredentialFormat]string `json:"credential_instance_ids"`
	// The number of credential instances left per credential format (in case they were issued in batches)
	BatchInstanceCountsRemaining map[CredentialFormat]*uint `json:"batch_instance_counts_remaining"`
	// All the attributes and their values in this credential
	Attributes []Attribute `json:"attributes"`
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires
	ExpiryDate int64 `json:"expiry_date"`
	// Whether or not this credential has been revoked
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential
	RevocationSupported bool `json:"revocation_supported"`
	// Url at which this credential can be issued (if any)
	IssueURL *TranslatedString `json:"issue_url"`
}

// CredentialDescriptor describes a credential without any values for the attributes
type CredentialDescriptor struct {
	CredentialId string            `json:"credential_id"`
	Name         TranslatedString  `json:"name"`
	Issuer       TrustedParty      `json:"issuer"`
	Category     *TranslatedString `json:"category"`
	ImagePath    string            `json:"image_path"`
	Attributes   []Attribute       `json:"attributes"`
	IssueURL     *TranslatedString `json:"issue_url"`
}

type CredentialStoreItem struct {
	Credential CredentialDescriptor `json:"credential"`
	Faq        Faq                  `json:"faq"`
}

type Faq struct {
	Intro   *TranslatedString `json:"intro"`
	Purpose *TranslatedString `json:"purpose"`
	Content *TranslatedString `json:"content"`
	HowTo   *TranslatedString `json:"how_to"`
}

func (client *Client) GetCredentialStore() ([]*CredentialStoreItem, error) {
	irmaConfig := client.GetIrmaConfiguration()
	result := []*CredentialStoreItem{}

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

		attributes := []Attribute{}

		for _, attr := range cred.AttributeTypes {
			attributes = append(attributes, Attribute{
				Id:          attr.ID,
				DisplayName: TranslatedString(attr.Name),
				Value: &AttributeValue{
					Type: displayHintToAttributeType(attr.DisplayHint),
				},
			})
		}

		result = append(result, &CredentialStoreItem{
			Credential: CredentialDescriptor{
				CredentialId: cred.Identifier().String(),
				Name:         TranslatedString(cred.Name),
				Issuer: TrustedParty{
					Id:   issuer.Identifier().String(),
					Name: TranslatedString(issuer.Name),
					// TODO: figure out where these should come from
					ImagePath: nil,
					Parent:    nil,
				},
				IssueURL:   convertOptionalTranslatedString(cred.IssueURL),
				Category:   convertOptionalTranslatedString(cred.Category),
				ImagePath:  cred.Logo(irmaConfig),
				Attributes: attributes,
			},
			Faq: Faq{
				Intro:   convertOptionalTranslatedString(cred.FAQIntro),
				Purpose: convertOptionalTranslatedString(cred.FAQPurpose),
				Content: convertOptionalTranslatedString(cred.FAQContent),
				HowTo:   convertOptionalTranslatedString(cred.FAQHowto),
			},
		})
	}

	return result, nil
}

func convertOptionalTranslatedString(s *irma.TranslatedString) *TranslatedString {
	if s == nil {
		return nil
	}
	t := TranslatedString(*s)
	return &t
}

// creates a credential descriptor containing only the attributes specified
func createCredentialDescriptor(
	irmaConfig *irma.Configuration,
	attrs []*irmaclient.DisclosureCandidate,
) (*CredentialDescriptor, error) {
	id := attrs[0].Type.CredentialTypeIdentifier()
	info, ok := irmaConfig.CredentialTypes[id]

	if !ok {
		return nil, fmt.Errorf("failed to find credential info for %s", id.String())
	}

	issuerId := info.IssuerIdentifier()
	issuer := irmaConfig.Issuers[issuerId]
	attributes := []Attribute{}

	// only put the requested attributes in the descriptor
	for _, at := range attrs {
		for _, a := range info.AttributeTypes {
			if a.GetAttributeTypeIdentifier() == at.Type {
				requestedValue := &AttributeValue{
					Type: AttributeType_TranslatedString,
				}
				if at.Value != nil {
					requestedValue.TranslatedString = convertOptionalTranslatedString(&at.Value)
				}
				attributes = append(attributes, Attribute{
					Id:             a.ID,
					DisplayName:    TranslatedString(a.Name),
					RequestedValue: requestedValue,
				})
			}
		}
	}

	return &CredentialDescriptor{
		CredentialId: info.Identifier().String(),
		Name:         TranslatedString(info.Name),
		Issuer: TrustedParty{
			Id:   issuer.ID,
			Name: TranslatedString(issuer.Name),
			// TODO: figure out where the issuer logo's come from
			ImagePath: nil,
			// TODO: figure out what it means to be on the Yivi trust chain
			Parent: nil,
		},
		Category:   convertOptionalTranslatedString(info.Category),
		ImagePath:  info.Logo(irmaConfig),
		Attributes: attributes,
		IssueURL:   convertOptionalTranslatedString(info.IssueURL),
	}, nil
}

func getCredentialDescriptor(irmaConfig *irma.Configuration, id irma.CredentialTypeIdentifier) (*CredentialDescriptor, error) {
	info, ok := irmaConfig.CredentialTypes[id]

	if !ok {
		return nil, fmt.Errorf("failed to find credential info for %s", id.String())
	}

	issuerId := info.IssuerIdentifier()
	issuer := irmaConfig.Issuers[issuerId]
	attributes := []Attribute{}

	for _, at := range info.AttributeTypes {
		attributes = append(attributes, Attribute{
			Id:          at.ID,
			DisplayName: TranslatedString(at.Name),
			Value: &AttributeValue{
				Type: AttributeType_String,
			},
		})
	}

	return &CredentialDescriptor{
		CredentialId: info.Identifier().String(),
		Name:         TranslatedString(info.Name),
		Issuer: TrustedParty{
			Id:   issuer.ID,
			Name: TranslatedString(issuer.Name),
			// TODO: figure out where the issuer logo's come from
			ImagePath: nil,
			// TODO: figure out what it means to be on the Yivi trust chain
			Parent: nil,
		},
		Category:   convertOptionalTranslatedString(info.Category),
		ImagePath:  info.Logo(irmaConfig),
		Attributes: attributes,
		IssueURL:   convertOptionalTranslatedString(info.IssueURL),
	}, nil
}

func credentialInfoListToSchemaless(irmaConfig *irma.Configuration, creds irma.CredentialInfoList) ([]*Credential, error) {
	result := []*Credential{}
	intermediateResult := map[string]*Credential{}

	// loop over all credentials and immediately combine them when they're the same
	// attributes + credential ID in different credential formats
	for _, cred := range creds {
		instanceHash, err := hashAttributesAndCredType(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to hash attributes and cred type: %w", err)
		}

		format := CredentialFormat(cred.CredentialFormat)

		// if there's an existing instance we just add some format specific info
		// and combine the two formats into a single credential result
		if existing, ok := intermediateResult[instanceHash]; ok {
			existing.BatchInstanceCountsRemaining[format] = cred.InstanceCount
			existing.CredentialInstanceIds[format] = cred.Hash
			// TODO: potentially add this informatino into format specific fields too
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
			attributes := []Attribute{}

			for _, at := range info.AttributeTypes {
				attrValue := cred.Attributes[at.GetAttributeTypeIdentifier()]
				attributes = append(attributes, Attribute{
					Id:          at.ID,
					DisplayName: TranslatedString(at.Name),
					Description: TranslatedString(at.Description),
					Value: &AttributeValue{
						Type:             displayHintToAttributeType(at.DisplayHint),
						TranslatedString: convertOptionalTranslatedString(&attrValue),
					},
				})
			}

			newCred := Credential{
				CredentialId: cred.Identifier().String(),
				Hash:         instanceHash,
				ImagePath:    info.Logo(irmaConfig),
				Name:         TranslatedString(info.Name),
				Issuer: TrustedParty{
					Id:   issuer.ID,
					Name: TranslatedString(issuer.Name),
					// TODO: figure out where the issuer logo's come from
					ImagePath: nil,
					// TODO: figure out what it means to be on the Yivi trust chain
					Parent: nil,
				},
				CredentialInstanceIds: map[CredentialFormat]string{
					format: cred.Hash,
				},
				BatchInstanceCountsRemaining: map[CredentialFormat]*uint{
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

func (client *Client) GetCredentials() ([]*Credential, error) {
	irmaConfig := client.GetIrmaConfiguration()
	creds := client.credentialInfoList()
	return credentialInfoListToSchemaless(irmaConfig, creds)
}

func displayHintToAttributeType(s string) AttributeType {
	result := AttributeType_TranslatedString
	switch s {
	case "portraitPhoto":
		result = AttributeType_Base64Image
	}
	return result
}

// SatisfiesRequestedAttributes checks that `given` contains everything needed to satisfy `requested`.
// Returns ok + list of issues with paths (e.g. "address.street", "roles[2]").
func SatisfiesRequestedAttributes(given, requested []Attribute) (bool, []string) {
	var issues []string
	checkAttributeList(&issues, "", given, requested)
	return len(issues) == 0, issues
}

func checkAttributeList(issues *[]string, path string, given, requested []Attribute) {
	givenByID := make(map[string]Attribute, len(given))
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

func checkValueSatisfies(issues *[]string, path string, given AttributeValue, req AttributeValue) {
	// Enforce type when requested type is set.
	if req.Type != "" && given.Type != req.Type {
		*issues = append(*issues, fmt.Sprintf("type mismatch at %s: have %q want %q", path, given.Type, req.Type))
		return
	}

	switch req.Type {
	case AttributeType_Object:
		// Nested attributes must satisfy nested requested constraints.
		checkAttributeList(issues, path, given.Object, req.Object)

	case AttributeType_Array:
		checkArrayAllOfUnordered(issues, path, given.Array, req.Array)

	case AttributeType_String:
		checkString(issues, path, given.String, req.String)

	case AttributeType_Int:
		if req.Int == nil {
			return
		}
		if given.Int == nil || *given.Int != *req.Int {
			*issues = append(*issues, fmt.Sprintf("int mismatch at %s", path))
		}

	case AttributeType_Bool:
		if req.Bool == nil {
			return
		}
		if given.Bool == nil || *given.Bool != *req.Bool {
			*issues = append(*issues, fmt.Sprintf("bool mismatch at %s", path))
		}

	case AttributeType_TranslatedString:
		if req.TranslatedString == nil {
			return
		}
		if given.TranslatedString == nil {
			*issues = append(*issues, fmt.Sprintf("translated_string missing at %s", path))
			return
		}
		// "All-of" on keys: requested languages must exist with same values.
		for lang, want := range *req.TranslatedString {
			have, ok := (*given.TranslatedString)[lang]
			if !ok || have != want {
				*issues = append(*issues, fmt.Sprintf("translated_string mismatch at %s.%s", path, lang))
			}
		}

	case AttributeType_Image:
		if req.ImagePath == nil {
			return
		}
		if given.ImagePath == nil || *given.ImagePath != *req.ImagePath {
			*issues = append(*issues, fmt.Sprintf("image mismatch at %s", path))
		}

	case AttributeType_Base64Image:
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

func checkString(issues *[]string, path string, given *string, req *string) {
	// If no specific requested string => only require presence? (or do nothing)
	// Here: if req is nil, we accept anything (since type already matched).
	if req == nil {
		return
	}

	// Special rule: requested "" means "present at all".
	if *req == "" {
		if given == nil {
			*issues = append(*issues, fmt.Sprintf("string missing at %s", path))
		}
		return
	}

	// Exact match required.
	if given == nil || *given != *req {
		*issues = append(*issues, fmt.Sprintf("string mismatch at %s", path))
	}
}

// Unordered "all-of":
// Every requested element must be satisfied by some *distinct* element in given.
// Uses backtracking to avoid greedy mismatches.
func checkArrayAllOfUnordered(issues *[]string, path string, given, req []AttributeValue) {
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
func valueSatisfiesNoReport(given AttributeValue, req AttributeValue) bool {
	if req.Type != "" && given.Type != req.Type {
		return false
	}

	switch req.Type {
	case AttributeType_Object:
		return attributeListSatisfiesNoReport(given.Object, req.Object)

	case AttributeType_Array:
		// Recurse into unordered all-of arrays as well.
		return arrayAllOfUnorderedNoReport(given.Array, req.Array)

	case AttributeType_String:
		if req.String == nil {
			return true
		}
		if *req.String == "" {
			return given.String != nil
		}
		return given.String != nil && *given.String == *req.String

	case AttributeType_Int:
		if req.Int == nil {
			return true
		}
		return given.Int != nil && *given.Int == *req.Int

	case AttributeType_Bool:
		if req.Bool == nil {
			return true
		}
		return given.Bool != nil && *given.Bool == *req.Bool

	case AttributeType_TranslatedString:
		if req.TranslatedString == nil {
			return true
		}
		if given.TranslatedString == nil {
			return false
		}
		for lang, want := range *req.TranslatedString {
			have, ok := (*given.TranslatedString)[lang]
			if !ok || have != want {
				return false
			}
		}
		return true

	case AttributeType_Image:
		if req.ImagePath == nil {
			return true
		}
		return given.ImagePath != nil && *given.ImagePath == *req.ImagePath

	case AttributeType_Base64Image:
		if req.Base64Image == nil {
			return true
		}
		return given.Base64Image != nil && *given.Base64Image == *req.Base64Image

	default:
		return true
	}
}

func arrayAllOfUnorderedNoReport(given, req []AttributeValue) bool {
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

func attributeListSatisfiesNoReport(given, requested []Attribute) bool {
	givenByID := make(map[string]Attribute, len(given))
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
