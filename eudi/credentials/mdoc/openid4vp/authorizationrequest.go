package openid4vp

import "mdoc"

// ============================================================
// AUTHORIZATION REQUEST — the single OpenID4VP request object carrying
// dcql_query together with the session-binding values
//
// Mirrors the relevant subset of
// github.com/privacybydesign/irmago/eudi/openid4vp's own
// AuthorizationRequest struct (openid4vp.go) — same field names/JSON
// tags — without importing it, the same way DCQLQuery/SessionTranscript
// already mirror openid4vp's shapes elsewhere in this package (see
// sessiontranscript.go's file comment, which already points at
// AuthorizationRequest's ClientId/Nonce/ResponseUri fields). Only the
// fields this profile actually uses are modeled: response_mode is always
// "direct_post" (the only mode Annex A §A.6 allows — see directpost.go),
// scope is omitted entirely since this profile exclusively uses
// dcql_query (the two are mutually exclusive per [OID4VP], and DCQLQuery
// is what this package already builds), and client_metadata/
// redirect_uri/request_uri_method are likewise out of scope.
//
// Before this file, clientId/nonce/responseUri were hardcoded as plain Go
// string literals implicitly shared between verifier and holder code
// (see cmd/demo/main.go) — this was the "no real Authorization Request
// being parsed" gap the README documented. NewAuthorizationRequest and
// SessionTranscript (below) are what actually close it: the holder now
// reads these values from a real parsed request object — the same way it
// already reads the DCQL query from receivedQuery rather than a shared
// Go variable — instead of a value that was simply "already known" to
// both sides.
// ============================================================

// directPostResponseMode is the only response_mode this profile models —
// Annex A §A.6 mandates OpenID4VP with response_mode=direct_post;
// direct_post.jwt (encrypted responses) isn't modeled (see
// sessiontranscript.go's file comment).
const directPostResponseMode = "direct_post"

// AuthorizationRequest is the OpenID4VP request a verifier sends a
// holder to start a presentation — carries the DCQL query alongside the
// session-binding values (client_id, nonce, response_uri) and the
// anti-CSRF state value, matching
// github.com/privacybydesign/irmago/eudi/openid4vp.AuthorizationRequest's
// field names/JSON tags for the subset this profile uses.
type AuthorizationRequest struct {
	ClientId     string    `json:"client_id"`
	DcqlQuery    DCQLQuery `json:"dcql_query"`
	Nonce        string    `json:"nonce"`
	ResponseMode string    `json:"response_mode"`
	ResponseUri  string    `json:"response_uri"`
	State        string    `json:"state"`
}

// NewAuthorizationRequest builds an Authorization Request for this
// profile, fixing response_mode to "direct_post".
func NewAuthorizationRequest(clientId, responseUri, nonce, state string, dcqlQuery DCQLQuery) AuthorizationRequest {
	return AuthorizationRequest{
		ClientId:     clientId,
		DcqlQuery:    dcqlQuery,
		Nonce:        nonce,
		ResponseMode: directPostResponseMode,
		ResponseUri:  responseUri,
		State:        state,
	}
}

// SessionTranscript builds the OpenID4VP SessionTranscript this request
// binds to, from the request's own ClientId/Nonce/ResponseUri — the
// holder-side convenience that replaces deriving NewOpenID4VPSessionTranscript's
// arguments from separately hardcoded/shared values.
func (r AuthorizationRequest) SessionTranscript() (mdoc.SessionTranscript, error) {
	return NewOpenID4VPSessionTranscript(r.ClientId, r.Nonce, r.ResponseUri)
}
