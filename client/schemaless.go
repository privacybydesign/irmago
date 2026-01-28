package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type TranslatedString map[string]string
type CredentialFormat string

type TrustedParty struct {
	Id string
	// Display name for the issuer
	Name TranslatedString
	// Url for the issuer (which can be different per language)
	Url *TranslatedString
	// Absolute path to the image for this issuer stored on disk
	ImagePath *string
	// The trust chain for this issuer (if any)
	Parent *TrustedParty
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
	// The type of the value. This should be one of the `AttributeType`s
	// See the table for `Value` to see what each `AttributeType` means
	Type AttributeType
	// |---------------------------------|-------------------------------|
	// | Attribute type                  | Data type                     |
	// |---------------------------------|-------------------------------|
	// | AttributeType_Object            | []Attribute                   |
	// | AttributeType_Array             | []AttributeValue              |
	// | AttributeType_String            | string                        |
	// | AttributeType_TranslatedString  | TranslatedString              |
	// | AttributeType_Bool              | bool                          |
	// | AttributeType_Int               | int                           |
	// | AttributeType_Image             | absolute path (string)        |
	// | AttributeType_Base64Image       | base64 encoded image (string) |
	// |---------------------------------|-------------------------------|
	Data any
}

type Attribute struct {
	// Id for this attribute (only the last part in case of irma/idemix)
	Id string
	// The name for this attribute as displayed to the end user
	DisplayName TranslatedString
	// The description for this attribute if any
	Description TranslatedString
	// The value to be displayed to the user
	Value AttributeValue
}

type Credential struct {
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for Eudi credentials this would be in the form of `https://example.credential.com`
	CredentialId string
	// Hash over all attribute values and the credential id.
	Hash string
	// Absolute path to the image for this credential stored on disk
	ImagePath string
	// The display name for this credential
	Name TranslatedString
	// All information about the credential issuer
	Issuer TrustedParty
	// The IDs for all instances of this credential in all different formats it's available in.
	CredentialInstanceIds map[CredentialFormat]string
	// The number of credential instances left per credential format (in case they were issued in batches)
	BatchInstanceCountsRemaining map[CredentialFormat]*uint
	// All the attributes and their values in this credential
	Attributes []Attribute
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64
	// The date and time (unix format) when this credential expires
	ExpiryDate int64
	// Whether or not this credential has been revoked
	Revoked bool
	// Whether or not revocation is supported for this credential
	RevocationSupported bool
	// Url at which this credential can be issued (if any)
	IssueURL *TranslatedString
}

// AttributeDescriptor is a description of an attribute without a value
type AttributeDescriptor struct {
	Id   string
	Name TranslatedString
	Type AttributeType
	// Only relevant when `Type` is `AttributeType_Object`
	Nested []AttributeDescriptor
}

type CredentialDescriptor struct {
	CredentialId string
	Name         TranslatedString
	Issuer       TrustedParty
	Category     *TranslatedString
	ImagePath    string
	Attributes   []AttributeDescriptor
	IssueURL     *TranslatedString
}

type CredentialStoreItem struct {
	Credential CredentialDescriptor
	Faq        Faq
}

type Faq struct {
	Intro   *TranslatedString
	Purpose *TranslatedString
	Content *TranslatedString
	HowTo   *TranslatedString
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

		attributes := []AttributeDescriptor{}

		for _, attr := range cred.AttributeTypes {
			attributes = append(attributes, AttributeDescriptor{
				Id:   attr.ID,
				Name: TranslatedString(attr.Name),
				Type: displayHintToAttributeType(attr.DisplayHint),
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

func find[T any](slice []T, pred func(T) bool) (T, bool) {
	for _, v := range slice {
		if pred(v) {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func (client *Client) getSdJwtCredentials() ([]*Credential, error) {
	creds := client.sdjwtvcStorage.GetCredentialMetdataList()

	result := []*Credential{}

	for _, rawCred := range creds {
		credMetadata, err := client.credentialMetadataStorage.Get(rawCred.CredentialType)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential metadata: %w", err)
		}
		issuerMetadata, err := client.issuerMetadataStorage.Get(credMetadata.IssuerId)
		if err != nil {
			return nil, fmt.Errorf("failed to get issuer metadata: %w", err)
		}

		attributes := []Attribute{}

		rawCredJson, _ := json.MarshalIndent(rawCred, "", "    ")
		irma.Logger.Infof("raw cred: %v", string(rawCredJson))

		for key, value := range rawCred.Attributes {
			valueJson, _ := json.MarshalIndent(value, "", "    ")
			irma.Logger.Infof("attribute %v: %v", key, string(valueJson))

			attributeMetadata, found := find(credMetadata.Attributes, func(item *irmaclient.AttributeMetadata) bool {
				return item.Id == key
			})
			if !found {
				continue
				// TODO: fix this bug...
				// return nil, fmt.Errorf("failed to get attribute metadata for: %v", key)
			}

			stringValue, isString := value.(string)
			nestedValues, isMap := value.(map[string]any)

			// TODO: make this recursive so it works for arbitrary levels of nesting
			if isMap {
				nestedAttributes := []Attribute{}
				for nestedKey, nestedValue := range nestedValues {
					nestedMetadata, found := find(attributeMetadata.Nested, func(item *irmaclient.AttributeMetadata) bool {
						return item.Id == nestedKey
					})
					if !found {
						continue
					}
					nestedAttributes = append(nestedAttributes, Attribute{
						Id:          nestedKey,
						DisplayName: TranslatedString(nestedMetadata.Name),
						Description: TranslatedString{},
						Value: AttributeValue{
							Type: AttributeType_String,
							Data: nestedValue,
						},
					})
				}
				attributes = append(attributes, Attribute{
					Id:          key,
					DisplayName: TranslatedString(attributeMetadata.Name),
					Description: TranslatedString{},
					Value: AttributeValue{
						Type: AttributeType_Object,
						Data: nestedAttributes,
					},
				})
			}
			if isString {
				attributes = append(attributes, Attribute{
					Id:          key,
					DisplayName: TranslatedString(attributeMetadata.Name),
					Description: TranslatedString{},
					Value: AttributeValue{
						Type: AttributeType_String,
						Data: stringValue,
					},
				})
			}

			irma.Logger.Infof("Attribute %v isString: %v, isMap: %v", key, isString, isMap)

		}

		tempImageUrl := issuerMetadata.LogoPath["en"]
		cred := Credential{
			CredentialId: rawCred.CredentialType,
			Hash:         rawCred.Hash,
			ImagePath:    tempImageUrl,
			Name:         TranslatedString(credMetadata.Name),
			Issuer: TrustedParty{
				Id:   credMetadata.IssuerId,
				Name: TranslatedString(issuerMetadata.Name),
				Url:  convertOptionalTranslatedString(&issuerMetadata.WebsiteUrl),
				// TODO: figure out a way to get this better
				ImagePath: &tempImageUrl,
				Parent:    nil,
			},
			CredentialInstanceIds: map[CredentialFormat]string{
				CredentialFormat(irmaclient.Format_SdJwtVc): rawCred.Hash,
			},
			BatchInstanceCountsRemaining: map[CredentialFormat]*uint{
				CredentialFormat(irmaclient.Format_SdJwtVc): &rawCred.RemainingInstanceCount,
			},
			Attributes:          attributes,
			IssuanceDate:        time.Time(rawCred.SignedOn).Unix(),
			ExpiryDate:          time.Time(rawCred.Expires).Unix(),
			Revoked:             false,
			RevocationSupported: false,
			IssueURL:            nil,
		}

		result = append(result, &cred)
	}

	return result, nil
}

func (client *Client) GetCredentials() ([]*Credential, error) {
	return client.getSdJwtCredentials()
	result := []*Credential{}

	irmaConfig := client.GetIrmaConfiguration()
	creds := client.CredentialInfoList()

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
					Value: AttributeValue{
						Type: displayHintToAttributeType(at.DisplayHint),
						Data: attrValue,
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

func displayHintToAttributeType(s string) AttributeType {
	result := AttributeType_TranslatedString
	switch s {
	case "portraitPhoto":
		result = AttributeType_Base64Image
	}
	return result
}
