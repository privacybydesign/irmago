package irma

import (
	"encoding/xml"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
	"path/filepath"
)

// This file contains data types for scheme managers, issuers, credential types
// matching the XML files in irma_configuration.

// SchemeManager describes a scheme manager.
type SchemeManager struct {
	ID                string           `xml:"Id"`
	Name              TranslatedString `xml:"Name"`
	URL               string           `xml:"Url"`
	Contact           string           `xml:"contact"`
	Demo              bool             `xml:"Demo"` // Decides whether to download private keys
	Description       TranslatedString
	MinimumAppVersion SchemeAppVersion
	KeyshareServer    string
	KeyshareWebsite   string
	KeyshareAttribute string
	TimestampServer   string
	XMLVersion        int      `xml:"version,attr"`
	XMLName           xml.Name `xml:"SchemeManager"`

	Status    SchemeManagerStatus `xml:"-"`
	Timestamp Timestamp

	storagepath string
	index       SchemeManagerIndex
}

type SchemeAppVersion struct {
	Android int `xml:"Android"`
	IOS     int `xml:"iOS"`
}

// Issuer describes an issuer.
type Issuer struct {
	ID              string           `xml:"ID"`
	Name            TranslatedString `xml:"Name"`
	SchemeManagerID string           `xml:"SchemeManager"`
	ContactAddress  string
	ContactEMail    string
	DeprecatedSince Timestamp
	XMLVersion      int `xml:"version,attr"`
}

// CredentialType is a description of a credential type, specifying (a.o.) its name, issuer, and attributes.
type CredentialType struct {
	ID                    string           `xml:"CredentialID"`
	Name                  TranslatedString `xml:"Name"`
	IssuerID              string           `xml:"IssuerID"`
	SchemeManagerID       string           `xml:"SchemeManager"`
	IsSingleton           bool             `xml:"ShouldBeSingleton"`
	DisallowDelete        bool             `xml:"DisallowDelete"`
	Description           TranslatedString
	AttributeTypes        []*AttributeType `xml:"Attributes>Attribute" json:"-"`
	RevocationServers     []string         `xml:"RevocationServers>RevocationServer"`
	RevocationUpdateCount uint64
	RevocationUpdateSpeed uint64
	RevocationIndex       int      `xml:"-"`
	XMLVersion            int      `xml:"version,attr"`
	XMLName               xml.Name `xml:"IssueSpecification"`

	IssueURL     TranslatedString `xml:"IssueURL"`
	IsULIssueURL bool             `xml:"IsULIssueURL"`

	DeprecatedSince Timestamp

	Dependencies CredentialDependencies

	ForegroundColor         string
	BackgroundGradientStart string
	BackgroundGradientEnd   string

	IsInCredentialStore bool
	Category            TranslatedString
	FAQIntro            TranslatedString
	FAQPurpose          TranslatedString
	FAQContent          TranslatedString
	FAQHowto            TranslatedString
	FAQSummary          *TranslatedString
}

// AttributeType is a description of an attribute within a credential type.
type AttributeType struct {
	ID          string `xml:"id,attr"`
	Optional    string `xml:"optional,attr"  json:",omitempty"`
	Name        TranslatedString
	Description TranslatedString

	RandomBlind bool `xml:"randomblind,attr,optional" json:",omitempty"`

	Index        int    `xml:"-"`
	DisplayIndex *int   `xml:"displayIndex,attr" json:",omitempty"`
	DisplayHint  string `xml:"displayHint,attr"  json:",omitempty"`

	RevocationAttribute bool `xml:"revocation,attr" json:",omitempty"`

	// Taken from containing CredentialType
	CredentialTypeID string `xml:"-"`
	IssuerID         string `xml:"-"`
	SchemeManagerID  string `xml:"-"`
}

// CredentialDependencies contains dependencies on credential types, using condiscon:
// a conjunction of disjunctions of conjunctions of credential types.
type CredentialDependencies [][][]CredentialTypeIdentifier

// RequestorScheme describes verified requestors
type RequestorScheme struct {
	ID        RequestorSchemeIdentifier `json:"id"`
	URL       string                    `json:"url"`
	Status    SchemeManagerStatus       `json:"-"`
	Timestamp Timestamp                 `json:"-"`

	storagepath string
	index       SchemeManagerIndex
	requestors  []*RequestorInfo
}

// RequestorInfo describes a single verified requestor
type RequestorInfo struct {
	Scheme     RequestorSchemeIdentifier `json:"scheme"`
	Name       TranslatedString          `json:"name"`
	Industry   *TranslatedString         `json:"industry"`
	Hostnames  []string                  `json:"hostnames"`
	Logo       *string                   `json:"logo"`
	ValidUntil *Timestamp                `json:"valid_until"`
	Wizards    map[string]*IssueWizard   `json:"wizards"`
}

// RequestorChunk is a number of verified requestors stored together. The RequestorScheme can consist of multiple such chunks
type RequestorChunk []*RequestorInfo

type (
	IssueWizard struct {
		ID       string                    `json:"id"`
		Title    TranslatedString          `json:"title"`
		Logo     *string                   `json:"logo,omitempty"`     // SHA256 of the logo contents (which is the filename on disk)
		LogoPath *string                   `json:"logoPath,omitempty"` // Full path to the logo set automatically during scheme parsing
		Issues   *CredentialTypeIdentifier `json:"issues,omitempty"`

		Info *TranslatedString `json:"info,omitempty"`
		FAQ  []IssueWizardQA   `json:"faq,omitempty"`

		Intro              *TranslatedString   `json:"intro,omitempty"`
		SuccessHeader      *TranslatedString   `json:"successHeader,omitempty"`
		SuccessText        *TranslatedString   `json:"successText,omitempty"`
		ExpandDependencies *bool               `json:"expandDependencies,omitempty"`
		Contents           IssueWizardContents `json:"contents"`
	}

	IssueWizardQA struct {
		Question TranslatedString `json:"question"`
		Answer   TranslatedString `json:"answer"`
	}

	// IssueWizardContents contains a condiscon (conjunction of disjunctions of conjunctions)
	// of issue wizard items, making it possible to present the user with different options
	// to complete the wizard.
	IssueWizardContents [][][]IssueWizardItem

	IssueWizardItem struct {
		Type       IssueWizardItemType       `json:"type"`
		Credential *CredentialTypeIdentifier `json:"credential,omitempty"`
		Header     *TranslatedString         `json:"header,omitempty"`
		Text       *TranslatedString         `json:"text,omitempty"`
		Label      *TranslatedString         `json:"label,omitempty"`
		SessionURL *string                   `json:"sessionUrl,omitempty"`
		URL        *TranslatedString         `json:"url,omitempty"`
		InApp      *bool                     `json:"inapp,omitempty"`
	}

	IssueWizardItemType string
)

const (
	IssueWizardItemTypeCredential IssueWizardItemType = "credential"
	IssueWizardItemTypeSession    IssueWizardItemType = "session"
	IssueWizardItemTypeWebsite    IssueWizardItemType = "website"

	maxWizardComplexity = 10
)

// Choose from the wizard a list of items.
//
// If the ExpandDependencies boolean is set to false, the result of IssueWizardContents.Choose
// is returned. If not set or set to true, this is augmented with all dependencies of all items
// in an executable order.
func (wizard IssueWizard) Choose(conf *Configuration, creds CredentialInfoList) ([]IssueWizardItem, error) {
	// convert creds slice to map for easy lookup
	credsmap := map[CredentialTypeIdentifier]struct{}{}
	for _, cred := range creds {
		credsmap[cred.Identifier()] = struct{}{}
	}

	contents := wizard.Contents.Choose(conf, credsmap)
	if wizard.ExpandDependencies != nil && !*wizard.ExpandDependencies {
		return contents, nil
	} else {
		return buildDependencyTree(contents, conf, credsmap)
	}
}

func buildDependencyTree(contents []IssueWizardItem, conf *Configuration, credsmap map[CredentialTypeIdentifier]struct{}) ([]IssueWizardItem, error) {
	// Each item in contents refers to a credential type that has dependencies, which may themselves
	// have dependencies. So each item has a tree of dependencies. We must return a list
	// containing all dependencies of each item in an executable order, i.e. item n in the
	// list depends only on items < n in the list. We do this as follows:
	// - by considering element n in items to be dependent on element n-1, we join all
	//   dependency trees into one
	// - of that tree, starting at the leaf nodes and iterating downwards toward the root,
	//   we put all items in the result list.

	// We assume here that if one wizard item depends on another, and that dependency is not defined
	// in the corresponding credential type issuer scheme, then they are put in the correct order in
	// the wizard in the requestor scheme: first a credential not depending on any other item in the
	// wizard, then an item that may depend on the first item, etc.
	// Below we iterate per level over the tree (root = level 0, its dependencies = level 1, their
	// dependencies = level 2, etc). Before that iteration, we don't yet know how many levels there
	// are. So the only logical starting point for this iteration is level 0, the root - i.e., the
	// last item of the contents slice. So we first reverse contents.
	reversed := make([]IssueWizardItem, 0, len(contents))
	byID := map[CredentialTypeIdentifier]IssueWizardItem{}
	skipped := 0
	for i := len(contents) - 1; i >= 0; i-- {
		item := contents[i]
		if item.Credential == nil {
			// If an item does not denote what credential it issues, we cannot take it into account -
			// just ignore it here and append it back to the end of the wizard just before returning.
			skipped++
			continue
		}
		reversed = append(reversed, contents[i])
		byID[*contents[i].Credential] = contents[i]
	}

	// Build a map containing per level of the dependency tree the (deduplicated) nodes at that level
	deps := credentialDependencies{}
	bylevel := map[int]map[CredentialTypeIdentifier]struct{}{}
	for i, item := range reversed {
		if err := wizardItemVisit(bylevel, i, *item.Credential, conf, deps, credsmap); err != nil {
			return nil, err
		}
	}

	// Scanning horizontally, i.e. per level, we iterate across the tree, putting all
	// credential types that we come across in the result slice. This starts at the leaf nodes
	// that have no dependencies, and after that across the intermediate nodes whose dependencies
	// have been put in the result slice in previous iterations.
	var result []IssueWizardItem                         // to return
	resultmap := map[CredentialTypeIdentifier]struct{}{} // to keep track of credentials already put in the result slice
	for i := len(bylevel) - 1; i >= 0; i-- {
		for id := range bylevel[i] {
			if _, ok := resultmap[id]; ok {
				continue
			}
			resultmap[id] = struct{}{}
			if item, present := byID[id]; present {
				result = append(result, item)
			} else {
				current := id // create copy of loop variable to take address of
				result = append(result, IssueWizardItem{
					Type:       IssueWizardItemTypeCredential,
					Credential: &current,
				})
			}
		}
	}

	result = append(result, contents[len(contents)-skipped:]...)
	return result, nil
}

type credentialDependencies map[CredentialTypeIdentifier][]IssueWizardItem

// wizardItemVisit is a recursive function that populates a map containing per level of a tree the
// (deduplicated) nodes at that level.
func wizardItemVisit(
	bylevel map[int]map[CredentialTypeIdentifier]struct{},
	level int,
	id CredentialTypeIdentifier,
	conf *Configuration,
	deps credentialDependencies,
	creds map[CredentialTypeIdentifier]struct{},
) error {
	if bylevel[level] == nil {
		bylevel[level] = map[CredentialTypeIdentifier]struct{}{}
	}
	bylevel[level][id] = struct{}{}

	for _, child := range deps.get(id, conf, creds) {
		if err := wizardItemVisit(bylevel, level+1, *child.Credential, conf, deps, creds); err != nil {
			return err
		}
	}
	return nil
}

// get returns the credential dependencies of the specified credential. If not present in the map
// it caches them before returning; on later invocations for the same credential the cached output
// is returned.
func (deps credentialDependencies) get(id CredentialTypeIdentifier, conf *Configuration, creds map[CredentialTypeIdentifier]struct{}) []IssueWizardItem {
	if _, present := deps[id]; !present {
		deps[id] = conf.CredentialTypes[id].Dependencies.WizardContents().Choose(conf, creds)
	}
	return deps[id]
}

// Process the wizard contents given the list of present credentials. Of each disjunction,
// either the first contained inner conjunction that is satisfied by the credential list is chosen;
// or if no such conjunction exists in the disjunction, the first conjunction is chosen.
// The result of doing this for all outer conjunctions is flattened and returned.
func (contents IssueWizardContents) Choose(conf *Configuration, creds map[CredentialTypeIdentifier]struct{}) []IssueWizardItem {
	var choice []IssueWizardItem
	for _, discon := range contents {
		disconSatisfied := false
		for _, con := range discon {
			conSatisfied := true
			for _, item := range con {
				if item.Credential == nil {
					// If it is not known what credential this item will issue (if any), then we cannot
					// compare that credential to the list of present credentials to establish whether
					// or not this item is completed. So we cannot consider the item to be completed,
					// thus neither can we consider the containing conjunction as completed.
					conSatisfied = false
					break
				}
				if _, present := creds[*item.Credential]; !present {
					conSatisfied = false
					break
				}
			}
			if conSatisfied {
				choice = append(choice, con...)
				disconSatisfied = true
				break
			}
		}
		if !disconSatisfied {
			choice = append(choice, discon[0]...)
		}
	}

	return choice
}

func (wizard *IssueWizard) Validate(conf *Configuration) error {
	conf.validateTranslations(fmt.Sprintf("issue wizard %s", wizard.ID), wizard)

	if (wizard.SuccessHeader == nil) != (wizard.SuccessText == nil) {
		return errors.New("wizard contents must have success header and text either both specified, or both empty")
	}
	// validate that no possible content graph is too complex
	allRelevantPaths := wizard.Contents.buildValidationPaths(conf, map[CredentialTypeIdentifier]struct{}{})
	for _, contents := range allRelevantPaths {
		// validate expanded dependency tree if ExpandDependencies flag is set to true; otherwise validate current length
		if wizard.ExpandDependencies == nil || *wizard.ExpandDependencies {
			result, error := buildDependencyTree(contents, conf, map[CredentialTypeIdentifier]struct{}{})

			if error != nil {
				return error
			}

			if len(result) >= maxWizardComplexity {
				return errors.Errorf("wizard with wizard ID %s too complex", wizard.ID)
			}
		} else {
			if len(contents) >= maxWizardComplexity {
				return errors.Errorf("wizard with wizard ID %s too complex", wizard.ID)
			}
		}
	}

	// validate translations, IssueWizardItems and FAQSummaries of dependencies
	shouldBeLast := false
	for i, outer := range wizard.Contents {
		for j, middle := range outer {
			for k, item := range middle {
				// validate all non-credential-items of a wizard are at the end
				if item.Type != "credential" {
					shouldBeLast = true
				} else {
					if shouldBeLast {
						return errors.Errorf("non-credential types in wizard %s should come last", wizard.ID)
					}
				}

				if err := item.validate(conf); err != nil {
					return errors.Errorf("item %d.%d.%d of issue wizard %s: %w", i, j, k, wizard.ID, err)
				}
				conf.validateTranslations(fmt.Sprintf("item %d.%d.%d of issue wizard %s", i, j, k, wizard.ID), item)
			}
		}
	}
	conf.validateTranslations(fmt.Sprintf("issue wizard %s", wizard.ID), wizard)
	for i, qa := range wizard.FAQ {
		conf.validateTranslations(fmt.Sprintf("QA %d of issue wizard %s", i, wizard.ID), qa)
	}

	return nil
}

func (contents IssueWizardContents) buildValidationPaths(conf *Configuration, creds map[CredentialTypeIdentifier]struct{}) [][]IssueWizardItem {
	var all [][]IssueWizardItem
	var choice []IssueWizardItem
	for _, discon := range contents {
		disconSatisfied := false

		for i, con := range discon {
			if i > 0 {
				if !userHasCreds(discon[i], creds) {
					// Copy from the original creds map to the target updatedCreds map
					updatedCreds := map[CredentialTypeIdentifier]struct{}{}
					for key, value := range creds {
						updatedCreds[key] = value
					}

					// check the scenario where the user already has the cards from this discon
					for _, item := range discon[i] {
						updatedCreds[*item.Credential] = struct{}{}
					}

					all = append(all, contents.buildValidationPaths(conf, updatedCreds)...)
				}
			}

			conSatisfied := true
			for _, item := range con {
				if item.Credential == nil {
					// If it is not known what credential this item will issue (if any), then we cannot
					// compare that credential to the list of present credentials to establish whether
					// or not this item is completed. So we cannot consider the item to be completed,
					// thus neither can we consider the containing conjunction as completed.
					conSatisfied = false
					break
				}
				if _, present := creds[*item.Credential]; !present {
					conSatisfied = false
					break
				}
			}
			if conSatisfied {
				choice = appendItems(choice, con)
				disconSatisfied = true
				break
			}
		}
		if !disconSatisfied {
			choice = appendItems(choice, discon[0])
		}
	}

	all = append(all, choice)

	return all
}

func userHasCreds(items []IssueWizardItem, creds map[CredentialTypeIdentifier]struct{}) bool {
	for _, val := range items {
		if val.Credential != nil {
			if _, ok := creds[*val.Credential]; !ok {
				return false
			}
		}
	}
	return true
}

// appendItems appends IssueWizardItems to IssueWizardItems and deduplicates
func appendItems(existing []IssueWizardItem, toBeAdded []IssueWizardItem) []IssueWizardItem {
	withDuplicates := append(existing, toBeAdded...)
	credsItemMap := make(map[*CredentialTypeIdentifier]IssueWizardItem)
	var itemsNoCreds []IssueWizardItem
	for _, i := range withDuplicates {
		if i.Credential != nil {
			credsItemMap[i.Credential] = i
		} else {
			itemsNoCreds = append(itemsNoCreds, i)
		}
	}

	var updated []IssueWizardItem
	for _, i := range credsItemMap {
		updated = append(updated, i)
	}
	updated = append(updated, itemsNoCreds...)

	return updated
}

func (item *IssueWizardItem) validate(conf *Configuration) error {
	if item.Type != IssueWizardItemTypeCredential &&
		item.Type != IssueWizardItemTypeSession &&
		item.Type != IssueWizardItemTypeWebsite {
		return errors.New("unsupported wizard item type")
	}
	if item.Type == IssueWizardItemTypeCredential {
		if item.Credential == nil {
			return errors.New("wizard item has type credential, but no credential specified")
		}
	} else {
		if item.Header == nil || item.Label == nil || item.Text == nil {
			return errors.New("wizard item missing required information")
		}
	}
	if item.Type == IssueWizardItemTypeSession && item.SessionURL == nil {
		return errors.New("wizard item has type session, but no session URL specified")
	}
	if item.Type == IssueWizardItemTypeWebsite && item.URL == nil {
		return errors.New("wizard item has type website, but no session URL specified")
	}

	if item.Credential == nil || conf.SchemeManagers[item.Credential.SchemeManagerIdentifier()] == nil {
		return nil
	}

	// In `irma scheme verify` is run on a single requestor scheme, we cannot expect mentioned
	// credential types from other schemes to exist. So only require mentioned credential types
	// to exist if their containing scheme also exists
	if conf.CredentialTypes[*item.Credential] == nil {
		return errors.New("nonexisting credential type " + item.Credential.Name())
	}

	// The wizard item itself must either contain a text field or their its credential type must have a FAQSummary
	if item.Text != nil {
		if l := item.Text.validate(); len(l) > 0 {
			return errors.New("Wizard item text field incomplete for item with credential type: " + item.Credential.String())
		}
	} else {
		faqSummary := conf.CredentialTypes[*item.Credential].FAQSummary
		if faqSummary == nil {
			return errors.New("FAQSummary missing for wizard item with credential type: " + item.Credential.String())
		}
		if l := faqSummary.validate(); len(l) > 0 {
			return errors.New("FAQSummary missing for: " + item.Credential.String())
		}
	}

	// All dependencies of the the item and their dependencies must contain FAQSummaries
	if conf.CredentialTypes[*item.Credential].Dependencies != nil {
		depChain := DependencyChain{*item.Credential}
		if err := validateFAQSummary(*item.Credential, conf, depChain); err != nil {
			return err
		}
	}

	return nil
}

func validateFAQSummary(cred CredentialTypeIdentifier, conf *Configuration, validatedDeps DependencyChain) error {
	for _, outer := range conf.CredentialTypes[cred].Dependencies {
		for _, middle := range outer {
			for _, item := range middle {
				faqSummary := conf.CredentialTypes[item].FAQSummary
				updatedDeps := append(validatedDeps, item)

				if faqSummary == nil {
					return errors.New("FAQSummary missing for last item in chain: " + updatedDeps.String())
				}

				if l := faqSummary.validate(); len(l) > 0 {
					return errors.New("FAQSummary incomplete for last item in chain: " + updatedDeps.String())
				}

				if conf.CredentialTypes[item].Dependencies != nil {
					return validateFAQSummary(item, conf, updatedDeps)
				}
			}
		}
	}

	return nil
}

// NewRequestorInfo returns a Requestor with just the given hostname
func NewRequestorInfo(hostname string) *RequestorInfo {
	return &RequestorInfo{
		Name:      NewTranslatedString(&hostname),
		Hostnames: []string{hostname},
	}
}

func (ad AttributeType) GetAttributeTypeIdentifier() AttributeTypeIdentifier {
	return NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s.%s.%s", ad.SchemeManagerID, ad.IssuerID, ad.CredentialTypeID, ad.ID))
}

func (ad AttributeType) IsOptional() bool {
	return ad.Optional == "true"
}

// Returns indices of random blind attributes within this credentialtype
// The indices coincide with indices of an AttributeList (metadataAttribute at index 0)
func (ct *CredentialType) RandomBlindAttributeIndices() []int {
	indices := []int{}
	for i, at := range ct.AttributeTypes {
		if at.RandomBlind {
			indices = append(indices, i+1)
		}
	}
	return indices
}

func (ct *CredentialType) attributeTypeIdentifiers(indices []int) (ids []string) {
	for i, at := range ct.AttributeTypes {
		for _, j := range indices {
			if i == j {
				ids = append(ids, at.ID)
			}
		}
	}
	return
}

func (ct *CredentialType) RandomBlindAttributeNames() []string {
	return ct.attributeTypeIdentifiers(ct.RandomBlindAttributeIndices())
}

func (ct *CredentialType) RevocationSupported() bool {
	return len(ct.RevocationServers) > 0
}

// ContainsAttribute tests whether the specified attribute is contained in this
// credentialtype.
func (ct *CredentialType) ContainsAttribute(ai AttributeTypeIdentifier) bool {
	if ai.CredentialTypeIdentifier().String() != ct.Identifier().String() {
		return false
	}
	for _, desc := range ct.AttributeTypes {
		if desc.ID == ai.Name() {
			return true
		}
	}
	return false
}

// IndexOf returns the index of the specified attribute if present,
// or an error (and -1) if not present.
func (ct CredentialType) IndexOf(ai AttributeTypeIdentifier) (int, error) {
	if ai.CredentialTypeIdentifier() != ct.Identifier() {
		return -1, errors.New("Wrong credential type")
	}
	for i, description := range ct.AttributeTypes {
		if description.ID == ai.Name() {
			return i, nil
		}
	}
	return -1, errors.New("Attribute identifier not found")
}

func (ct CredentialType) AttributeType(ai AttributeTypeIdentifier) *AttributeType {
	i, _ := ct.IndexOf(ai)
	if i == -1 {
		return nil
	}
	return ct.AttributeTypes[i]
}

// TranslatedString is a map of translated strings.
type TranslatedString map[string]string

type xmlTranslation struct {
	XMLName xml.Name
	Text    string `xml:",chardata"`
}

type xmlTranslatedString struct {
	Translations []xmlTranslation `xml:",any"`
}

// MarshalXML implements xml.Marshaler.
func (ts *TranslatedString) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	temp := &xmlTranslatedString{}
	for lang, text := range *ts {
		temp.Translations = append(temp.Translations,
			xmlTranslation{XMLName: xml.Name{Local: lang}, Text: text},
		)
	}
	return e.EncodeElement(temp, start)
}

// UnmarshalXML unmarshals an XML tag containing a string translated to multiple languages,
// for example: <Foo><en>Hello world</en><nl>Hallo wereld</nl></Foo>
// into a TranslatedString: { "en": "Hello world" , "nl": "Hallo wereld" }
func (ts *TranslatedString) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if map[string]string(*ts) == nil {
		*ts = TranslatedString(make(map[string]string))
	}
	temp := &xmlTranslatedString{}
	if err := d.DecodeElement(temp, &start); err != nil {
		return err
	}
	for _, translation := range temp.Translations {
		(*ts)[translation.XMLName.Local] = translation.Text
	}
	return nil
}

func (ts *TranslatedString) validate() []string {
	var invalidLangs []string
	for _, lang := range validLangs {
		if text, exists := (*ts)[lang]; !exists || text == "" {
			invalidLangs = append(invalidLangs, lang)

		}
	}
	return invalidLangs
}

func (deps CredentialDependencies) WizardContents() IssueWizardContents {
	var contents IssueWizardContents
	for _, credDiscon := range deps {
		discon := make([][]IssueWizardItem, 0, len(credDiscon))
		for _, credCon := range credDiscon {
			con := make([]IssueWizardItem, 0, len(credCon))
			for i := range credCon {
				con = append(con, IssueWizardItem{Type: IssueWizardItemTypeCredential, Credential: &(credCon[i])})
			}
			discon = append(discon, con)
		}
		contents = append(contents, discon)
	}
	return contents
}

func (deps *CredentialDependencies) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var temp struct {
		Or []struct {
			And []struct {
				Con []CredentialTypeIdentifier `xml:"CredentialType"`
			}
		}
	}
	if err := d.DecodeElement(&temp, &start); err != nil {
		return err
	}
	for _, discon := range temp.Or {
		t := make([][]CredentialTypeIdentifier, 0, len(discon.And))
		for _, con := range discon.And {
			t = append(t, con.Con)
		}
		*deps = append(*deps, t)
	}
	return nil
}

// Identifier returns the identifier of the specified credential type.
func (ct *CredentialType) Identifier() CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(ct.SchemeManagerID + "." + ct.IssuerID + "." + ct.ID)
}

// IssuerIdentifier returns the issuer identifier of the specified credential type.
func (ct *CredentialType) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(ct.SchemeManagerID + "." + ct.IssuerID)
}

func (ct *CredentialType) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(ct.SchemeManagerID)
}

func (ct *CredentialType) Logo(conf *Configuration) string {
	scheme := conf.SchemeManagers[ct.SchemeManagerIdentifier()]
	path := filepath.Join(scheme.path(), ct.IssuerID, "Issues", ct.ID, "logo.png")
	exists, err := common.PathExists(path)
	if err != nil || !exists {
		return ""
	}
	return path
}

// Identifier returns the identifier of the specified issuer description.
func (id *Issuer) Identifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.SchemeManagerID + "." + id.ID)
}

func (id *Issuer) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.SchemeManagerID)
}
