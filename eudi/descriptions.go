package eudi

type RelyingPartyRequestor struct {
	Requestor
	RelyingParty RelyingParty `json:"rp"`
}

type Requestor struct {
	Registration string       `json:"registration"`
	Organization Organization `json:"organization"`
}

type Organization struct {
	Logo      Logo              `json:"logo"`
	LegalName map[string]string `json:"legalName"` // TODO: current cert contains 'display_name' instead of 'legalName', so we need to change this
}

type Logo struct {
	MimeType string `json:"mimeType"`
	Data     []byte `json:"data"`
}

type RelyingParty struct {
	AuthorizedAttributes []CredentialDescriptor `json:"authorized"`
	RequestPurpose       map[string]string      `json:"purpose"`
}

type CredentialDescriptor struct {
	Credential string   `json:"credential"`
	Attributes []string `json:"attributes"`
}
