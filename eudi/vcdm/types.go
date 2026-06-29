package vcdm

import "time"

// CredentialEnvelope is the normalized VCDM representation used internally.
// Raw and format-specific artifacts can be carried alongside normalized fields.
type CredentialEnvelope struct {
	ID               string
	Contexts         []string
	Types            []string
	Issuer           string
	SubjectID        string
	IssuanceDate     *time.Time
	ExpirationDate   *time.Time
	ValidFrom        *time.Time
	ValidUntil       *time.Time
	Proofs           []Proof
	Status           *CredentialStatus
	TermsOfUse       []TermsOfUse
	Evidence         []Evidence
	CredentialSchema []CredentialSchema
	RelatedResource  []RelatedResource
	Claims           map[string]any

	// Original format identifier (e.g. dc+sd-jwt, jwt_vc_json).
	Format string
	// Raw credential material as received from issuer.
	RawCredential any
}

type Proof struct {
	Type               string
	Cryptosuite        string
	Created            *time.Time
	VerificationMethod string
	ProofPurpose       string
	ProofValue         string
}

type CredentialStatus struct {
	ID              string
	Type            string
	StatusPurpose   string
	StatusListURL   string
	StatusListIndex *int
}

type TermsOfUse struct {
	Type string
	ID   string
	URI  string
}

type Evidence struct {
	ID   string
	Type []string
	Data map[string]any
}

type CredentialSchema struct {
	ID   string
	Type string
}

type RelatedResource struct {
	ID        string
	Type      string
	Digest    string
	MediaType string
	URL       string
}
