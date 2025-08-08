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
	LegalName map[string]string `json:"legalName"`
}

type Logo struct {
	MimeType string `json:"mimeType"`
	Data     []byte `json:"data"`
}

type RelyingParty struct {
	// AuthorizedQueryableAttributeSets contains the sets of attributes that the relying party is allowed to query. In the future, this will be checked by the app to authorize disclosure queries.
	AuthorizedQueryableAttributeSets []QueryableAttributeSet `json:"authorized"`
	RequestPurpose                   map[string]string       `json:"purpose"`
}

type QueryableAttributeSet struct {
	Credential string   `json:"credential"`
	Attributes []string `json:"attributes"`
}
