package did

// DIDDocument represents a W3C DID Document.
type DIDDocument struct {
	Context            interface{}          `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRef    `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRef    `json:"assertionMethod,omitempty"`
	KeyAgreement       []VerificationRef    `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document.
type VerificationMethod struct {
	ID                 string      `json:"id"`
	Type               string      `json:"type"`
	Controller         string      `json:"controller"`
	PublicKeyJwk       interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string      `json:"publicKeyMultibase,omitempty"`
}

// VerificationRef can be either a string (reference) or an embedded VerificationMethod.
type VerificationRef interface{}

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
}
