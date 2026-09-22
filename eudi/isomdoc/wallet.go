package isomdoc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
)

// ============================================================
// THE REAL WALLET BEHIND AN org-iso-mdoc SESSION
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
//	services.RevealFromClaimPaths         the same claim-path reading
//	services.SelectiveDiscloseNamespaces  the same stripping
//	mdoc.DeviceKeyFromIssuerAuth          the same "which key must sign this"
//
// None of that is transport-specific, and every one of them is somewhere a second
// implementation would be free to drift. The genuinely new part of an
// org-iso-mdoc disclosure is small: the request arrived as CBOR from the browser
// instead of as a signed JWT over HTTPS, and the presentation is bound to a
// SessionTranscript built over the DC API handover instead of an OpenID4VP one.
// Session already owns both of those.
//
// # Why this is not mdoc_dcql.PrepareDisclosure
//
// That method does the same four steps and then goes further: it signs deviceAuth
// over a transcript it builds itself and returns base64 QueryResponses. Neither
// is usable here. The transcript is the session's — it hashes the EncryptionInfo
// text and the platform-supplied origin, neither of which a DCQL selection
// carries — and Selection deliberately hands back an UNSIGNED document plus the
// Holder that can sign it, so that signing happens once, in assemble, against the
// one transcript the reader shares. Composing below PrepareDisclosure rather than
// through it is what keeps a single signing site.

// DeviceKeyBinder resolves the device key an mdoc presentation must be signed
// with, given the device public key the credential's own MSO is bound to.
//
// Structurally identical to the interface mdoc_dcql declares, and satisfied by
// the same services.NewMdocDeviceKeyBinder — declared again here rather than
// imported so this package does not depend on an OpenID4VP one for a two-line
// seam. The point of the seam is what can replace it: an implementation backed by
// StrongBox, TrustZone or the Secure Enclave returns a mdoc.Holder built on a
// platform key handle, and the private half never enters the process.
type DeviceKeyBinder interface {
	HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.Holder, error)
}

// ConsentHandler is the wallet UI: it is shown what the reader asked for and
// returns what the user agreed to.
//
// The plan and the choices are the SAME types the OpenID4VP consent screen uses
// (clientmodels.DisclosurePlan in, clientmodels.DisclosureDisconSelection out), so
// an app that can already render a disclosure request can render an org-iso-mdoc
// one without a second screen.
//
// Returning no choices is a refusal, and is expected rather than exceptional: it
// produces a response carrying documentErrors, not a failed session.
type ConsentHandler interface {
	RequestConsent(ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error)
}

// ConsentRequest is what the user is being asked to approve.
type ConsentRequest struct {
	// Query is the reader's request in the wallet's own query language, built
	// from what each document PERMITS rather than from what was asked. Carried so
	// the caller can hold the reader to the authorized attribute sets in its
	// certificate — the same check the OpenID4VP path applies, and the reason a
	// verifier refused online is refused here.
	Query dcql.DcqlQuery

	// Plan is the pick-one structure the UI renders.
	Plan *clientmodels.DisclosurePlan

	// QueryIds runs parallel to the plan's pick-ones and records which DCQL query
	// each candidate answers. Pass it back through unchanged; it is what
	// dcql.SelectionsFromChoices needs to route a choice to its query.
	QueryIds []dcql.ChoiceQueryIds

	// Documents is the per-document detail from the ISO request, including the
	// authenticated reader identity and what 7.2.1 withheld from an
	// unauthenticated one. This is what an org-iso-mdoc consent screen can show
	// that an OpenID4VP one cannot: who the platform says is asking, and what they
	// asked for and are not getting.
	Documents []RequestedDocument

	// Origin is the web origin the platform authenticated for the caller. It is
	// the only identity an unauthenticated reader has, and the value the response
	// is cryptographically bound to, so a consent screen naming who is asking
	// should name this.
	Origin string
}

// WalletDiscloser implements Discloser, Committer and Releaser against the
// wallet's real storage.
//
// Not safe for concurrent use, and not reusable across transactions: it holds the
// instances reserved for one disclosure between Disclose and Commit.
type WalletDiscloser struct {
	queries    *dcql.DcqlHandler
	instances  *services.MdocInstanceSelector
	deviceKeys DeviceKeyBinder
	consent    ConsentHandler

	// reserved holds the instances chosen for this disclosure, unspent until
	// Commit. See Committer for why the two are separate.
	reserved []*services.ReservedInstance
}

// NewWalletDiscloser wires an org-iso-mdoc session to the wallet's own machinery.
//
// queries should be the same dcql.DcqlHandler the OpenID4VP flow uses, so a
// request arriving over the DC API searches exactly the credentials an online
// request would. deviceKeys is the same binder mdoc_dcql is constructed with.
func NewWalletDiscloser(
	queries *dcql.DcqlHandler,
	instances *services.MdocInstanceSelector,
	deviceKeys DeviceKeyBinder,
	consent ConsentHandler,
) *WalletDiscloser {
	return &WalletDiscloser{queries: queries, instances: instances, deviceKeys: deviceKeys, consent: consent}
}

var (
	_ Discloser = (*WalletDiscloser)(nil)
	_ Committer = (*WalletDiscloser)(nil)
	_ Releaser  = (*WalletDiscloser)(nil)
)

// Disclose runs candidate selection, asks the user, and reserves the instances
// their answer commits to.
func (w *WalletDiscloser) Disclose(request DisclosureRequest) ([]Selection, error) {
	if w.queries == nil || w.instances == nil || w.deviceKeys == nil || w.consent == nil {
		return nil, fmt.Errorf(
			"wallet discloser is missing its query handler, instance selector, device key binder or consent handler")
	}
	// Any reservation still held here belongs to a disclosure that never
	// finished. Releasing before reserving again keeps a reused discloser from
	// stranding instances until the wallet restarts.
	w.Release()

	// From PERMITTED, not from what the reader asked: 7.2.1 has already run.
	query, err := DcqlQueryFromPermittedDocuments(request.Documents)
	if errors.Is(err, ErrNothingServable) {
		// Nothing may be released, so there is nothing to put to the user.
		// Consent screens for requests that can only be refused are noise, and the
		// reader still learns the outcome: assemble reports every requested
		// document that is not returned as a documentError.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("translate device request: %w", err)
	}

	candidates, err := w.queries.FindCandidates(query)
	if err != nil {
		return nil, fmt.Errorf("find candidates: %w", err)
	}

	// 8.3.2.1.2.1: "The mdoc shall ignore all unknown data elements in a device
	// retrieval mdoc request when processing the request." See narrow.
	if narrowed, changed := w.narrow(query, candidates); changed {
		retried, retryErr := w.queries.FindCandidates(narrowed)
		if retryErr != nil {
			return nil, fmt.Errorf("find candidates for narrowed request: %w", retryErr)
		}
		query, candidates = narrowed, retried
	}

	// No previous plan and no pre-existing hashes: issuance-during-disclosure is an
	// OpenID4VP flow that sends the user to an issuer mid-session over the web.
	// There is no such detour here — the DC API call is synchronous and the browser
	// is waiting on it.
	plan, queryIds, err := w.queries.BuildDisclosurePlan(query, candidates, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("build disclosure plan: %w", err)
	}

	choices, err := w.consent.RequestConsent(ConsentRequest{
		Query:     query,
		Plan:      plan,
		QueryIds:  queryIds,
		Documents: request.Documents,
		Origin:    request.Origin,
	})
	if err != nil {
		return nil, fmt.Errorf("consent: %w", err)
	}
	if len(choices) == 0 {
		return nil, nil // a refusal, reported to the reader as documentErrors
	}

	return w.presentationsFor(dcql.SelectionsFromChoices(choices, queryIds))
}

// presentationsFor turns the user's DCQL selections into the documents to present:
// one reserved instance each, stripped to what was chosen, with the holder that
// can sign it.
//
// Signing is NOT done here. The document leaves without a DeviceSigned and
// assemble attaches one over the session transcript, which is the only place that
// transcript exists — see the header comment on why this is not
// mdoc_dcql.PrepareDisclosure.
func (w *WalletDiscloser) presentationsFor(selections []dcql.DisclosureSelection) ([]Selection, error) {
	presented := make([]Selection, 0, len(selections))

	for _, selection := range selections {
		reserved, err := w.instances.Reserve(selection.CredentialHash)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("reserve an instance of credential %s: %w", selection.CredentialHash, err)
		}
		// Recorded before anything else can fail, so the release below covers it.
		w.reserved = append(w.reserved, reserved)

		reveal, err := services.RevealFromClaimPaths(selection.ClaimPaths)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("read claim paths of selected credential %s: %w", selection.CredentialHash, err)
		}

		// Shared with the OpenID4VP path deliberately: the same stored credential
		// must be stripped identically however it was asked for, or it would reveal
		// different things depending on the transport.
		disclosed, err := services.SelectiveDiscloseNamespaces(&reserved.Document, reveal)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("selective disclosure for credential %s: %w", selection.CredentialHash, err)
		}

		// Which key must sign is asked of the CREDENTIAL, not of any key record
		// joined to it: the MSO's deviceKeyInfo is what the issuer bound this
		// document to and what the verifier checks the signature against, so a
		// signer resolved from it is the only one that can produce a presentation
		// that verifies. The private half stays behind the binder, which is what
		// allows it to live in hardware.
		deviceKey, err := mdoc.DeviceKeyFromIssuerAuth(disclosed.IssuerSigned.IssuerAuth)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("read device key of stored instance %s: %w", reserved.Instance.ID, err)
		}
		holder, err := w.deviceKeys.HolderForDeviceKey(deviceKey)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("no device key available to sign for instance %s: %w", reserved.Instance.ID, err)
		}

		presented = append(presented, Selection{
			DocType:  disclosed.DocType,
			Document: *disclosed,
			Holder:   holder,
		})
	}

	return presented, nil
}

// Commit spends every instance this disclosure reserved.
//
// Called by Session only once the response is assembled and sealed, which is the
// first point at which nothing further can fail. Reserving and spending are
// separate for exactly that reason — see services.MdocInstanceSelector.Spend.
func (w *WalletDiscloser) Commit() error {
	for _, reserved := range w.reserved {
		if err := w.instances.Spend(reserved); err != nil {
			return err
		}
	}
	w.reserved = nil
	return nil
}

// Release gives up every instance this disclosure reserved and did not spend.
//
// Called by Session on every path out, including the successful one, and by this
// file whenever a disclosure abandons instances it had already taken. Spending
// releases as it goes, so a Commit that failed halfway leaves exactly the unspent
// remainder here, and releasing an instance twice does nothing.
func (w *WalletDiscloser) Release() {
	if w.instances == nil {
		return
	}
	w.instances.Release(w.reserved...)
	w.reserved = nil
}

// ============================================================
// PARTIAL SATISFACTION — ISO/IEC 18013-5 8.3.2.1.2.1
// ============================================================
//
// "The mdoc shall ignore all unknown data elements in a device retrieval mdoc
// request when processing the request" — a shall, and the reason narrow exists.
//
// The reporting half is not. 8.3.2.1.2.2's wording is "If the device retrieval
// mdoc response structure does not include some data element or document
// requested in the device retrieval mdoc request, an error code MAY be returned
// as part of the documentErrors or errors structures", and Table 9 code 0 is
// "Data not returned … This element may be used in all cases." So answering with
// what you have is required; saying what you could not is permitted.
//
// This package does both anyway, and the pairing is the argument: narrowing
// alone silently answers a smaller question than the reader asked, which is the
// one outcome a reader cannot detect. Reporting turns it into a partial answer
// the reader can see is partial. See assemble.
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
// The dropped elements are NOT lost. assemble computes the response's `errors`
// against the ORIGINAL ItemsRequest the reader sent, never the narrowed query, so
// every element asked for and not returned is reported with Table 9's code whether
// it was dropped here, withheld by 7.2.1, or never held at all. That is the
// truthful answer in every case: it was requested, and it is not being returned.
//
// # What it deliberately does not do
//
//   - **It never widens.** Only claims already in the query survive, so narrowing
//     cannot cause an element the reader did not ask for to be disclosed. The query
//     it narrows is itself already the permitted one, so narrowing can only ever
//     move further away from disclosing something.
//   - **It leaves a query with claim_sets alone.** Those are the verifier's own
//     explicit statement of which combinations it will accept, and dropping claims
//     out of a set would answer a question it did not ask. (18013-5 has no such
//     concept, so the translations in request.go never emit them; the guard is for a
//     caller that hands this discloser a query from somewhere else.)
//   - **It gives up rather than guessing when nothing is individually satisfiable,
//     or when narrowing still finds no candidate.** The second case is real: the
//     claims may be individually held but spread across two credentials, and one
//     credential query answers from one credential. The reader then gets the
//     documentError it would have got anyway.
//   - **It costs one query per claim, and only on the path that already failed.** A
//     request answered as asked never reaches it.
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
