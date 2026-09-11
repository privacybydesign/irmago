package proximity

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
)

// ============================================================
// THE REAL WALLET BEHIND A PROXIMITY SESSION
// ============================================================
//
// Session defines Discloser and deliberately does not implement it: finding
// candidates, asking the user and spending a single-use instance are wallet
// concerns, not ISO 18013-5 ones. This file is the wallet's side of that
// boundary, and it is built almost entirely out of machinery that already exists.
//
// What it reuses, and why each matters:
//
//	dcql.DcqlHandler.FindCandidates       the same candidate search OpenID4VP runs
//	dcql.DcqlHandler.BuildDisclosurePlan  the same pick-one plan the UI renders
//	dcql.SelectionsFromChoices            the same "which query does this answer"
//	services.MdocInstanceSelector         the same instance choice and burn
//	services.SelectiveDiscloseNamespaces  the same stripping
//
// None of that is proximity-specific, and every one of them is somewhere a second
// implementation would be free to drift. The genuinely new part of a proximity
// disclosure is small: the request arrived as CBOR over a radio instead of as a
// signed JWT over HTTPS, and the presentation is bound to a SessionTranscript
// instead of an OpenID4VP handover. Session already owns both of those.

// ConsentHandler is the wallet UI: it is shown what the reader asked for and
// returns what the user agreed to.
//
// The plan and the choices are the SAME types the OpenID4VP consent screen uses
// (clientmodels.DisclosurePlan in, clientmodels.DisclosureDisconSelection out), so
// an app that can already render a disclosure request can render a proximity one
// without a second screen.
//
// Returning no choices is a refusal, and is expected rather than exceptional: it
// produces a response carrying documentErrors, not a failed session.
type ConsentHandler interface {
	// RequestConsent is handed the reader's request, the plan built from the
	// wallet's actual holdings, and the reader's identity where it authenticated.
	RequestConsent(ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error)
}

// ConsentRequest is what the user is being asked to approve.
type ConsentRequest struct {
	// Query is the reader's request in the wallet's own query language, as handed to
	// the DCQL pipeline. Carried so the caller can hold the reader to the
	// authorized attribute sets in its certificate — the same check the OpenID4VP
	// path applies, and the reason a verifier refused online is refused in person.
	Query dcql.DcqlQuery

	// Plan is the pick-one structure the UI renders.
	Plan *clientmodels.DisclosurePlan

	// QueryIds runs parallel to the plan's pick-ones and records which DCQL query
	// each candidate answers. Pass it back through unchanged; it is what
	// dcql.SelectionsFromChoices needs to route a choice to its query.
	QueryIds []dcql.ChoiceQueryIds

	// Documents is the per-document detail from the ISO request, including the
	// authenticated reader identity. This is what a proximity consent screen can
	// show that an OpenID4VP one cannot: who is physically asking.
	Documents []RequestedDocument
}

// WalletDiscloser implements Discloser (and Committer) against the wallet's real
// storage.
//
// Not safe for concurrent use, and not reusable across transactions: it holds the
// instances reserved for one disclosure between Disclose and Commit.
type WalletDiscloser struct {
	queries   *dcql.DcqlHandler
	instances *services.MdocInstanceSelector
	consent   ConsentHandler

	// reserved holds the instances chosen for this disclosure, unspent until
	// Commit. See Committer for why the two are separate.
	reserved []*services.ReservedInstance
}

// NewWalletDiscloser wires a proximity session to the wallet's own machinery.
//
// queries should be the same dcql.DcqlHandler the OpenID4VP flow uses, so a
// proximity request searches exactly the credentials an online request would.
func NewWalletDiscloser(
	queries *dcql.DcqlHandler,
	instances *services.MdocInstanceSelector,
	consent ConsentHandler,
) *WalletDiscloser {
	return &WalletDiscloser{queries: queries, instances: instances, consent: consent}
}

var (
	_ Discloser = (*WalletDiscloser)(nil)
	_ Committer = (*WalletDiscloser)(nil)
)

// Disclose runs candidate selection, asks the user, and reserves the instances
// their answer commits to.
func (w *WalletDiscloser) Disclose(request DisclosureRequest) ([]Selection, error) {
	if w.queries == nil || w.instances == nil || w.consent == nil {
		return nil, fmt.Errorf("wallet discloser is missing its query handler, instance selector or consent handler")
	}
	w.reserved = nil

	query := request.Query
	candidates, err := w.queries.FindCandidates(query)
	if err != nil {
		return nil, fmt.Errorf("find candidates for proximity request: %w", err)
	}

	// 8.3.2.1.2.1: "The mdoc shall ignore all unknown data elements in a device
	// retrieval mdoc request when processing the request." See narrow.
	if narrowed, changed := w.narrow(query, candidates); changed {
		retried, retryErr := w.queries.FindCandidates(narrowed)
		if retryErr != nil {
			return nil, fmt.Errorf("find candidates for narrowed proximity request: %w", retryErr)
		}
		query, candidates = narrowed, retried
	}

	// No previous plan and no pre-existing hashes: issuance-during-disclosure is an
	// OpenID4VP flow that sends the user to an issuer mid-session over the web, and
	// there is no such detour in a device retrieval transaction — the reader is
	// standing in front of the holder and the link is point to point.
	plan, queryIds, err := w.queries.BuildDisclosurePlan(query, candidates, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("build disclosure plan for proximity request: %w", err)
	}

	choices, err := w.consent.RequestConsent(ConsentRequest{
		Plan:      plan,
		QueryIds:  queryIds,
		Documents: request.Documents,
	})
	if err != nil {
		return nil, fmt.Errorf("consent: %w", err)
	}
	if len(choices) == 0 {
		return nil, nil // a refusal, reported to the reader as documentErrors
	}

	return w.reserveFor(dcql.SelectionsFromChoices(choices, queryIds))
}

// reserveFor turns the user's DCQL selections into the documents to present.
func (w *WalletDiscloser) reserveFor(selections []dcql.DisclosureSelection) ([]Selection, error) {
	presented := make([]Selection, 0, len(selections))

	for _, selection := range selections {
		reserved, err := w.instances.Reserve(selection.CredentialHash)
		if err != nil {
			return nil, err
		}

		reveal, err := services.RevealFromClaimPaths(selection.ClaimPaths)
		if err != nil {
			return nil, fmt.Errorf("read claim paths of selected credential %s: %w", selection.CredentialHash, err)
		}

		w.reserved = append(w.reserved, reserved)
		presented = append(presented, Selection{Document: reserved.Document, Reveal: reveal})
	}

	return presented, nil
}

// Commit spends every instance this disclosure reserved.
//
// Called by Session only once the response is assembled, which is the first point
// at which nothing further can fail. Reserving and spending are separate for
// exactly that reason — see services.MdocInstanceSelector.Spend.
func (w *WalletDiscloser) Commit() error {
	for _, reserved := range w.reserved {
		if err := w.instances.Spend(reserved); err != nil {
			return err
		}
	}
	w.reserved = nil
	return nil
}

// ============================================================
// PARTIAL SATISFACTION — ISO/IEC 18013-5 8.3.2.1.2.1
// ============================================================
//
// "The mdoc shall ignore all unknown data elements in a device retrieval mdoc
// request when processing the request", with 8.3.2.1.2.2's `errors` member to
// report them. Together: answer with what you have, and say what you could not.
//
// # Why anything is needed here at all
//
// DCQL is all-or-nothing without claim_sets: a credential that cannot satisfy
// EVERY claim of a credential query is not a candidate for it. So a reader asking
// an mDL for ten elements, one of which this wallet does not hold, got no
// candidate, no document, and a documentError — where the clause wants the other
// nine returned and the tenth reported.
//
// The translation step cannot fix this and says so: which elements are unknown
// depends on what the wallet holds, which is not known until candidate selection
// has run. It has to happen after a search comes back empty, which is here.
//
// # What narrow does
//
// For each credential query that found nothing, it asks which of its claims are
// individually satisfiable — one probe query per claim, through the SAME
// FindCandidates path, so "held" means exactly what the handler means by it rather
// than what a shortcut into storage would mean — and drops the rest.
//
// The dropped elements are NOT lost. Session.buildDocument computes the response's
// `errors` against the ORIGINAL ItemsRequest the reader sent, never the narrowed
// query, so every element asked for and not returned is reported with Table 9's
// code whether it was dropped here or never held at all. That is the truthful
// answer in both cases: it was requested, and it is not being returned.
//
// # What it deliberately does not do
//
//   - **It never widens.** Only claims already in the query survive, so narrowing
//     cannot cause an element the reader did not ask for to be disclosed.
//   - **It leaves a query with claim_sets alone.** Those are the verifier's own
//     explicit statement of which combinations it will accept, and dropping claims
//     out of a set would answer a question it did not ask. (18013-5 has no such
//     concept, so DcqlQueryFromDeviceRequest never emits them; the guard is for a
//     caller that hands this discloser a query from somewhere else.)
//   - **It gives up rather than guessing when nothing is individually satisfiable,
//     or when narrowing still finds no candidate.** The second case is real: the
//     claims may be individually held but spread across two credentials, and one
//     credential query answers from one credential. The reader then gets the
//     documentError it would have got anyway.
//   - **It costs one query per claim, and only on the path that already failed.**
//     A request answered as asked never reaches it.
func (w *WalletDiscloser) narrow(query dcql.DcqlQuery, found *dcql.DcqlResult) (dcql.DcqlQuery, bool) {
	if found == nil {
		return query, false
	}

	narrowed := query
	narrowed.Credentials = make([]dcql.CredentialQuery, len(query.Credentials))
	copy(narrowed.Credentials, query.Credentials)

	changed := false
	for i, credentialQuery := range query.Credentials {
		if result, ok := found.QueryResults[credentialQuery.Id]; ok && len(result.OwnedCandidates) > 0 {
			continue // answerable as asked
		}
		// Nothing to narrow to: a single claim narrowed to nothing is just a refusal,
		// and claim_sets are the verifier's own alternatives.
		if len(credentialQuery.Claims) < 2 || len(credentialQuery.ClaimSets) > 0 {
			continue
		}

		kept := w.satisfiableClaims(credentialQuery)
		if len(kept) == 0 || len(kept) == len(credentialQuery.Claims) {
			// Nothing held, or everything held and the query failed for some other
			// reason (an expired batch, a docType mismatch). Narrowing answers
			// neither, so leave the query as the reader wrote it.
			continue
		}

		narrowed.Credentials[i].Claims = kept
		changed = true
	}

	return narrowed, changed
}

// satisfiableClaims returns the claims of one credential query that the wallet can
// answer on their own, in the order the reader asked for them.
//
// Each probe carries the query's own Meta, Format and TrustedAuthorities so that
// "satisfiable" means satisfiable FOR THIS QUERY — a credential of the right
// docType holding the element — rather than merely somewhere in the wallet. The
// probe carries no CredentialSets, since those reference query ids that are not in
// it.
func (w *WalletDiscloser) satisfiableClaims(credentialQuery dcql.CredentialQuery) []dcql.Claim {
	kept := make([]dcql.Claim, 0, len(credentialQuery.Claims))

	for _, claim := range credentialQuery.Claims {
		probe := credentialQuery
		probe.Claims = []dcql.Claim{claim}
		probe.ClaimSets = nil

		result, err := w.queries.FindCandidates(dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{probe},
		})
		if err != nil {
			// A probe that cannot run says nothing about the claim. Treating it as
			// unheld would silently drop an element the wallet may well hold.
			continue
		}
		if answered, ok := result.QueryResults[probe.Id]; ok && len(answered.OwnedCandidates) > 0 {
			kept = append(kept, claim)
		}
	}

	return kept
}
