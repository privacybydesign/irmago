// Package isomdoc presents mdocs the way ISO/IEC 18013-5 asks for them: a
// DeviceRequest in, a DeviceResponse out.
//
// It exists because that exchange needs to know about two things at once — the
// 18013-5 wire format, and how this wallet finds credentials and asks the user
// about them — and neither neighbouring package should know about the other.
// eudi/credentials/mdoc is deliberately a near-leaf holding the structures and
// their cryptography, which is what keeps the OpenID4VP handovers out of it; the
// wallet's own machinery (candidate selection, consent, single-use instance
// accounting) lives in eudi/services and eudi/openid4vp/dcql and is shared with
// OpenID4VP rather than copied for this.
//
// # The transport is an edge, not the subject
//
// Today a DeviceRequest reaches this wallet one way: the W3C Digital Credentials
// API's org-iso-mdoc protocol, where the bytes come from the browser and the
// response is sealed with HPKE against a browser-supplied origin.
//
// The transport is kept at the edge anyway. Everything between the request and
// the response — the query, the consent screen, the selective disclosure, the
// deviceAuth over a session transcript — is a property of ISO 18013-5 and not of
// how the bytes arrived, and writing it as though it were would mean rewriting it
// for the next way they arrive. A property that held on one route and not another
// (an unlinkability guarantee, an instance spent twice, a reader authenticated on
// one path only) looks exactly like nothing being broken.
//
// This package was called `proximity` when BLE device retrieval was the intended
// route. That work is parked and the name was wrong for what remained.
package isomdoc

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// DcqlQueryFromDeviceRequest translates a reader's DeviceRequest (8.3.2.1.2.1)
// into the DCQL query the wallet already knows how to answer.
//
// The point is to reuse rather than duplicate: candidate selection, claim
// matching, the consent screen and the disclosure log all run off dcql.DcqlQuery
// today, and a proximity request that arrives as one gets all of it unchanged.
// Nothing about DCQL is being claimed as part of 18013-5 — this is an internal
// representation, and the wire in both directions stays CBOR.
//
// The mapping, per DocRequest:
//
//	docType                      -> Meta.DocTypeValue
//	nameSpaces[ns][element]      -> Claim{Path: [ns, element]}
//	                     value   -> Claim.IntentToRetain
//
// # A known difference in semantics
//
// 8.3.2.1.2.1 ends with "The mdoc shall ignore all unknown data elements in a
// device retrieval mdoc request when processing the request", and 8.3.2.1.2.2
// gives the DeviceResponse an `errors` member to report elements it could not
// return. Together those describe partial satisfaction: answer with what you have.
//
// DCQL is all-or-nothing in the absence of claim_sets — a credential that cannot
// satisfy every claim is not a candidate — so a request naming one element this
// wallet does not hold currently yields no candidate at all, where 18013-5 would
// have the mdoc return the rest and report the remainder as errors.
//
// That gap is left open deliberately rather than papered over here, because it
// cannot be closed at translation time: which elements are unknown depends on what
// the wallet holds, which is not known until candidate selection has run. It
// belongs to the step that builds the DeviceResponse. Recorded so the eventual
// fix is made there and not by weakening the query.
func DcqlQueryFromDeviceRequest(request mdoc.DeviceRequest) (dcql.DcqlQuery, error) {
	if err := request.Validate(); err != nil {
		return dcql.DcqlQuery{}, err
	}

	requested := make([]mdoc.ItemsRequest, 0, len(request.DocRequests))
	for i, docRequest := range request.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return dcql.DcqlQuery{}, fmt.Errorf("docRequests[%d]: %w", i, err)
		}
		requested = append(requested, items)
	}
	return dcqlQueryFrom(requested)
}

// DcqlQueryFromPermittedDocuments translates documents the session has already
// evaluated, taking each one's PERMITTED items rather than what the reader asked
// for.
//
// This is the translation a Discloser wants and DcqlQueryFromDeviceRequest is
// not. By the time a disclosure is being planned, reader authentication has run
// and 7.2.1 has decided what an unauthenticated reader is entitled to; building
// the query from the raw DeviceRequest at that point would undo that decision
// silently — the withheld elements would reach candidate selection, the consent
// screen and the disclosure log, and the only thing keeping them out of the
// response would be that nothing later put them in.
//
// Documents that can serve nothing at all are skipped rather than translated to
// an empty query: a credential query with no claims is refused by the mso_mdoc
// handler, so including one would fail the whole request over a document that was
// never going to be answered. They are still reported to the reader — see the
// documentErrors loop in assemble, which works from the session's full document
// list and not from this query.
func DcqlQueryFromPermittedDocuments(documents []RequestedDocument) (dcql.DcqlQuery, error) {
	permitted := make([]mdoc.ItemsRequest, 0, len(documents))
	for _, document := range documents {
		if !document.Servable() {
			continue
		}
		permitted = append(permitted, document.Permitted)
	}
	if len(permitted) == 0 {
		// Nothing may be released. An empty DcqlQuery is not valid, and there is
		// no question to put to the user, so this is reported as the refusal it is
		// rather than as a malformed query.
		return dcql.DcqlQuery{}, ErrNothingServable
	}
	return dcqlQueryFrom(permitted)
}

// ErrNothingServable reports a request none of whose documents may be served —
// an unauthenticated reader asking only for elements 7.2.1 does not release. It
// is a refusal, answered with documentErrors, and not a failure of the session.
var ErrNothingServable = errors.New("no requested document may be served to this reader")

// dcqlQueryFrom builds the query both translations produce, so the two cannot
// drift in what an mdoc request means in DCQL.
func dcqlQueryFrom(requested []mdoc.ItemsRequest) (dcql.DcqlQuery, error) {
	credentials := make([]dcql.CredentialQuery, 0, len(requested))
	for i, items := range requested {
		credentials = append(credentials, dcql.CredentialQuery{
			Id:     queryId(i),
			Format: string(clientmodels.Format_MsoMdoc),
			Meta:   &dcql.Meta{DocTypeValue: items.DocType},
			Claims: claimsFor(items),
			// Multiple stays false: a DocRequest asks for one document of one
			// docType. A reader wanting two asks twice.
			//
			// RequireHolderBinding stays nil, which DCQL reads as true. There is
			// no unbound proximity presentation: 9.1.3 has the mdoc authenticate
			// every DeviceResponse with deviceAuth over the session transcript,
			// and that is the whole reason the session has a transcript.
		})
	}

	query := dcql.DcqlQuery{Credentials: credentials}
	// No CredentialSets: without them DCQL requires every credential query to be
	// answered, which is what a DeviceRequest asking for several documents means.
	if err := query.Validate(); err != nil {
		return dcql.DcqlQuery{}, fmt.Errorf("translated DeviceRequest is not a valid query: %w", err)
	}
	return query, nil
}

// queryId names a DocRequest for the rest of the pipeline.
//
// The docType would be the obvious identifier and cannot be used: DCQL requires an
// id "consisting of alphanumeric, underscore or hyphen characters", and every real
// docType is dotted — "org.iso.18013.5.1.mDL". The index is unique within the
// request, which is all the id has to be, and stable, which keeps the consent
// screen and the response ordering reproducible.
func queryId(index int) string {
	return queryIdPrefix + strconv.Itoa(index)
}

// queryIdPrefix is the fixed prefix every generated query id carries.
const queryIdPrefix = "doc"

// claimsFor flattens nameSpaces into DCQL claims.
//
// Order is the reason this is not a plain range over the maps. Go randomises map
// iteration, and these claims reach the user: an unordered consent screen would
// list the same request differently on each presentation, which is a bad way to
// ask someone to agree to something and makes the disclosure log harder to compare
// against the request. Sorting also makes the translation testable.
func claimsFor(items mdoc.ItemsRequest) []dcql.Claim {
	namespaces := make([]string, 0, len(items.NameSpaces))
	for namespace := range items.NameSpaces {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	var claims []dcql.Claim
	for _, namespace := range namespaces {
		elements := items.NameSpaces[namespace]
		identifiers := make([]string, 0, len(elements))
		for identifier := range elements {
			identifiers = append(identifiers, identifier)
		}
		sort.Strings(identifiers)

		for _, identifier := range identifiers {
			claims = append(claims, dcql.Claim{
				Path: []any{namespace, identifier},
				// Carried, never acted on. The mdoc cannot enforce a promise about
				// what the verifier does after the transaction; what it can do is
				// make sure the person deciding sees the promise. dcql.Claim
				// documents the same rule for the OpenID4VP side.
				IntentToRetain: elements[identifier],
			})
		}
	}
	return claims
}
