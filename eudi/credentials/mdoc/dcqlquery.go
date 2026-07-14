package mdoc

import "fmt"

// ============================================================
// DCQL QUERY — how a verifier requests attributes over OpenID4VP
//
// The AV Blueprint's Annex A §A.6 mandates OpenID4VP as the presentation
// mechanism for this profile and states "The DCQL query and response as
// defined in Section 6 of [OID4VP] MUST be used." DCQL (Digital
// Credentials Query Language) is JSON, not the ISO 18013-5 native
// DeviceRequest CBOR object — that CBOR object is only used by the W3C
// Digital Credentials API path, which isn't modeled here.
//
// These types mirror the subset of
// github.com/privacybydesign/irmago/eudi/openid4vp/dcql's DcqlQuery/
// CredentialQuery/Meta/Claim shape this profile actually needs (same
// JSON field names/nesting), rather than importing that package —
// mdoc is deliberately its own Go module with no dependency on the rest
// of irmago (see go.mod), the same way sessiontranscript.go mirrors
// openid4vp's field shapes without importing it.
// ============================================================

// mdocDCQLFormat is the DCQL "format" value for ISO 18013-5 mdoc
// credentials, confirmed against the AV Blueprint's own worked example:
// {"format": "mso_mdoc", "meta": {"doctype_value": "eu.europa.ec.av.1"}, ...}
const mdocDCQLFormat = "mso_mdoc"

// DCQLQuery is the top-level object carried as the OpenID4VP Authorization
// Request's dcql_query parameter.
type DCQLQuery struct {
	Credentials []DCQLCredentialQuery `json:"credentials"`
}

// DCQLCredentialQuery requests one credential. Id identifies this query
// within the query and, correspondingly, within the vp_token response —
// see NewVPTokenJSON.
type DCQLCredentialQuery struct {
	Id     string      `json:"id"`
	Format string      `json:"format"`
	Meta   DCQLMeta    `json:"meta"`
	Claims []DCQLClaim `json:"claims"`
}

// DCQLMeta narrows the query to a specific mdoc docType.
type DCQLMeta struct {
	DocTypeValue string `json:"doctype_value"`
}

// DCQLClaim requests one attribute. Path is always a 2-element
// [namespace, elementIdentifier] pair for mdoc credentials — e.g.
// ["eu.europa.ec.av.1", "age_over_18"], matching the AV Blueprint's own
// worked example exactly.
type DCQLClaim struct {
	Path []string `json:"path"`
}

// NewDCQLQuery builds a DCQL query asking for the given attributes
// (namespace + elementIdentifier per this profile's single-namespace
// shape) for docType. Unlike ISO 18013-5's native DeviceRequest, DCQL has
// no intentToRetain concept — there's nothing to set it to, so it's
// simply absent, not defaulted to some value.
func NewDCQLQuery(id, docType, namespace string, attributes []string) DCQLQuery {
	claims := make([]DCQLClaim, len(attributes))
	for i, attr := range attributes {
		claims[i] = DCQLClaim{Path: []string{namespace, attr}}
	}
	return DCQLQuery{
		Credentials: []DCQLCredentialQuery{{
			Id:     id,
			Format: mdocDCQLFormat,
			Meta:   DCQLMeta{DocTypeValue: docType},
			Claims: claims,
		}},
	}
}

// RequestedAttributes extracts the namespace and requested attribute list
// for docType from a DCQL query — the holder-side counterpart to
// NewDCQLQuery. Every claim's path must be a 2-element [namespace,
// elementIdentifier] pair sharing the same namespace; anything else is
// rejected as malformed for this single-namespace profile.
func (q DCQLQuery) RequestedAttributes(docType string) (namespace string, attributes []string, err error) {
	for _, cq := range q.Credentials {
		if cq.Format != mdocDCQLFormat || cq.Meta.DocTypeValue != docType {
			continue
		}
		if len(cq.Claims) == 0 {
			return "", nil, fmt.Errorf("credential query for %q has no claims", docType)
		}
		attrs := make([]string, 0, len(cq.Claims))
		for _, claim := range cq.Claims {
			if len(claim.Path) != 2 {
				return "", nil, fmt.Errorf("claim path %v is not a 2-element [namespace, elementIdentifier] path", claim.Path)
			}
			switch {
			case namespace == "":
				namespace = claim.Path[0]
			case claim.Path[0] != namespace:
				return "", nil, fmt.Errorf("claim path %v uses namespace %q, expected %q", claim.Path, claim.Path[0], namespace)
			}
			attrs = append(attrs, claim.Path[1])
		}
		return namespace, attrs, nil
	}
	return "", nil, fmt.Errorf("no credential query found for docType %q with format %q", docType, mdocDCQLFormat)
}

// CredentialQueryId returns the Id of the credential query matching
// docType — the key under which the holder's response must be placed in
// the vp_token (see NewVPTokenJSON). Returns an error under the same
// conditions as RequestedAttributes.
func (q DCQLQuery) CredentialQueryId(docType string) (string, error) {
	for _, cq := range q.Credentials {
		if cq.Format == mdocDCQLFormat && cq.Meta.DocTypeValue == docType {
			return cq.Id, nil
		}
	}
	return "", fmt.Errorf("no credential query found for docType %q with format %q", docType, mdocDCQLFormat)
}
