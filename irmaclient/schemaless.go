package irmaclient

import (
	"fmt"

	irma "github.com/privacybydesign/irmago"
)

// A description of a CA in a chain of trust that can be used to tell the
// user about the chain
type CertificateAuthority struct {
	// The parent of this CA (nil if root)
	Parent *CertificateAuthority
	// The human readable name for this CA
	Name irma.TranslatedString
	// A description for this CA, telling the user who it is
	Description irma.TranslatedString
	// The url for this CA
	Url string
}

type Issuer struct {
	Id string
	// Display name for the issuer
	Name irma.TranslatedString
	// Url for the issuer (which can be different per language)
	Url irma.TranslatedString
	// Absolute path to the image for this issuer stored on disk
	ImagePath string
	// The trust chain for this issuer (if any)
	TrustChain *CertificateAuthority
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
)

type AttributeValue struct {
	// The type of the value. This should be one of the `AttributeType`s
	// See the table for `Value` to see what each `AttributeType` means
	Type AttributeType
	// | --------------------------------|-------------------------|
	// | Attribute type                  | Value type              |
	// | --------------------------------|-------------------------|
	// | AttributeType_Object            | Attribute               |
	// | AttributeType_Array             | []AttributeValue        |
	// | AttributeType_String            | string                  |
	// | AttributeType_TranslatedString  | irma.TranslatedString   |
	// | AttributeType_Bool              | bool                    |
	// | AttributeType_Int               | int                     |
	// | AttributeType_Image             | absolute path (string)  |
	// | --------------------------------|-------------------------|
	Value any
}

type Attribute struct {
	// Id for this attribute (only the last part in case of irma/idemix)
	Id string
	// The name for this attribute as displayed to the end user
	DisplayName irma.TranslatedString
	// The description for this attribute if any
	Description irma.TranslatedString
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
	Name irma.TranslatedString
	// All information about the credential issuer
	Issuer Issuer
	// The IDs for all instances of this credential in all different formats it's available in.
	CredentialInstanceIds map[CredentialFormat]string
	// The number of credential instances left per credential format (in case they were issued in batches)
	BatchInstanceCountsRemaining map[CredentialFormat]*int
	// All the attributes and their values in this credential
	Attributes []Attribute
}

func (client *Client) GetCredentials() ([]Credential, error) {
	result := []Credential{}

	irmaConfig := client.GetIrmaConfiguration()
	creds := client.CredentialInfoList()

	for _, cred := range creds {
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
				DisplayName: at.Name,
				Description: at.Description,
				Value: AttributeValue{
					Type:  AttributeType_String,
					Value: attrValue,
				},
			})
		}

		newCred := Credential{
			CredentialId: cred.Identifier().String(),
			Hash:         cred.Hash,
			ImagePath:    info.Logo(irmaConfig),
			Name:         info.Name,
			Issuer: Issuer{
				Id:   issuer.ID,
				Name: issuer.Name,
				Url:  *info.IssueURL,
				// TODO: figure out where the issuer logo's come from
				ImagePath: "",
				// TODO: figure out what it means to be on the Yivi trust chain
				TrustChain: nil,
			},
			CredentialInstanceIds: map[CredentialFormat]string{
				// cred.CredentialFormat: cred.Hash,
			},
			BatchInstanceCountsRemaining: map[CredentialFormat]*int{},
			Attributes:                   attributes,
		}

		result = append(result, newCred)
	}

	return result, nil
}
