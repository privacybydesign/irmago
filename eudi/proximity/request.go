// Package proximity carries the parts of ISO/IEC 18013-5 device retrieval that
// have to know about both the mdoc wire format and the wallet's own machinery.
//
// eudi/credentials/mdoc is deliberately a near-leaf: it holds the 18013-5
// structures and their cryptography and nothing about how this wallet finds
// credentials or asks the user about them. That boundary is what keeps the
// OpenID4VP handovers out of it, and it is worth keeping for proximity too. So the
// translation below — 18013-5 request to the wallet's internal query language —
// lives here rather than in either package it joins.
package proximity

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

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

	credentials := make([]dcql.CredentialQuery, 0, len(request.DocRequests))
	for i, docRequest := range request.DocRequests {
		items, err := docRequest.Items()
		if err != nil {
			return dcql.DcqlQuery{}, fmt.Errorf("docRequests[%d]: %w", i, err)
		}
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

// queryIdPrefix is shared by queryId and queryIndex so the two cannot drift.
const queryIdPrefix = "doc"

// queryIndex reads a DocRequest's position back out of the id queryId gave it.
//
// This is what lets a selection be matched to the request it answers rather than
// to the first request of the same docType — see Selection.QueryId for why those
// are not the same thing. Reported as not-an-index rather than guessed at for an
// id this package did not mint: a Discloser is free to answer a query built
// somewhere else, and "doc" followed by something that is not a number says
// nothing about which DocRequest was meant.
func queryIndex(id string) (int, bool) {
	digits, found := strings.CutPrefix(id, queryIdPrefix)
	if !found || digits == "" {
		return 0, false
	}
	index, err := strconv.Atoi(digits)
	if err != nil || index < 0 {
		return 0, false
	}
	return index, true
}

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
