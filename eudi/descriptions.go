package eudi

type RequestorSchemeData struct {
	Logo         RequestorSchemeLogo         `json:"logo"`
	Organisation RequestorSchemeOrganisation `json:"organisation"`
}

type RequestorSchemeOrganisation struct {
	DisplayName string `json:"display_name"` // TODO: current cert contains 'display_name' instead of 'displayName', so we need to change this
}

type RequestorSchemeLogo struct {
	MimeType string `json:"mimeType"`
	Data     []byte `json:"data"`
}
