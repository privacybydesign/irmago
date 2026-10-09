package isomdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
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
// StrongBox, TrustZone or the Secure Enclave returns a mdoc.DeviceSigner built on a
// platform key handle, and the private half never enters the process.
type DeviceKeyBinder interface {
	SignerForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.DeviceSigner, error)
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

	// authorizer holds a reader to its certificate. Optional: nil means the
	// check does not run, which is the right default for a caller that has no
	// scheme to read entitlements out of.
	authorizer ReaderAuthorizer

	// reserved holds the instances chosen for this disclosure, unspent until
	// Commit. See Committer for why the two are separate.
	//
	// Each carries the query it answers, because Commit spends only the
	// instances whose documents left as plain mdoc: an attestation presented as
	// a zero-knowledge proof is not consumed. Without the query id there is no
	// way back from "this document was proved" to "this instance", since a
	// response can carry a proof of one document and a disclosure of another.
	reserved []reservedFor

	// disclosed records what this disclosure handed over, for the caller to log.
	// See DisclosedCredential.
	disclosed []DisclosedCredential
}

// DisclosedCredential is one credential a disclosure released, in the terms the
// activity log needs: the stored batch it came from, what left the wallet, and
// what the verifier said about it.
//
// It exists because a disclosure that leaves no trace is a disclosure the user
// cannot audit, and org-iso-mdoc is the transport where that matters most: a
// zero-knowledge presentation is unlinkable and reveals nothing to anyone
// watching, so the wallet's own log is the only record the user will ever have
// that they proved something to somebody.
//
// Deliberately not a finished log entry. Building one needs display metadata, a
// logo store and a locale, none of which this package has or should acquire --
// services.BuildMdocLogCredential turns this into one.
type DisclosedCredential struct {
	// Batch is the stored batch the presented instance came from.
	Batch *models.MdocBatch

	// ClaimPaths are the paths that left the wallet.
	ClaimPaths [][]any

	// Claims are the verifier's own claims for this credential, carrying the
	// intentToRetain the user was shown.
	Claims []dcql.Claim
}

// Disclosed reports what the last Disclose handed over, for the caller to record
// in the activity log. Empty after a refusal, which is correct: nothing left.
func (w *WalletDiscloser) Disclosed() []DisclosedCredential {
	return w.disclosed
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

// WithReaderAuthorizer installs the check that holds an authenticated reader to
// the attribute sets its certificate is registered for.
//
// Chainable rather than a fifth constructor argument so that a caller which has
// no scheme — a test, or a build with no trust configuration — is not obliged to
// pass nil to say so.
func (w *WalletDiscloser) WithReaderAuthorizer(authorizer ReaderAuthorizer) *WalletDiscloser {
	w.authorizer = authorizer
	return w
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
	// Cleared with it: a reused discloser must not report the previous
	// disclosure as part of this one.
	w.disclosed = nil

	// From PERMITTED, not from what the reader asked: 7.2.1 has already run.
	query, err := DcqlQueryFromPermitted(request.Documents)
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

	// Before the first search, so narrowing sees it: an AV threshold is worth
	// presenting only when it is true, and a credential answering one false must
	// never become a candidate. See requireTrueThresholds.
	query, _ = requireTrueThresholds(query)

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

	// Before the user is asked anything: a reader gets to ask only for what its
	// certificate entitles it to ask for. See authorize.
	if err := w.authorize(request.Documents); err != nil {
		return nil, err
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

	return w.presentationsFor(query, dcql.SelectionsFromChoices(choices, queryIds))
}

// presentationsFor turns the user's DCQL selections into the documents to present:
// one reserved instance each, stripped to what was chosen, with the holder that
// can sign it.
//
// Signing is NOT done here. The document leaves without a DeviceSigned and
// assemble attaches one over the session transcript, which is the only place that
// transcript exists — see the header comment on why this is not
// mdoc_dcql.PrepareDisclosure.
func (w *WalletDiscloser) presentationsFor(
	query dcql.DcqlQuery, selections []dcql.DisclosureSelection,
) ([]Selection, error) {
	presented := make([]Selection, 0, len(selections))

	// The claims each selection answers, which SelectionsFromChoices does not
	// carry: dcql.DcqlHandler.PrepareDisclosure attaches them on its way to a
	// format handler, and this path composes below that method rather than
	// through it. Resolving them here is what keeps the intentToRetain the user
	// was shown from being dropped on the way to the activity log.
	claimsByQuery := make(map[string][]dcql.Claim, len(query.Credentials))
	for _, credentialQuery := range query.Credentials {
		claimsByQuery[credentialQuery.Id] = credentialQuery.Claims
	}

	for _, selection := range selections {
		reserved, err := w.instances.Reserve(selection.CredentialHash)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("reserve an instance of credential %s: %w", selection.CredentialHash, err)
		}
		// Recorded before anything else can fail, so the release below covers it.
		w.reserved = append(w.reserved, reservedFor{queryID: selection.QueryId, instance: reserved})

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
		signer, err := w.deviceKeys.SignerForDeviceKey(deviceKey)
		if err != nil {
			w.Release()
			return nil, fmt.Errorf("no device key available to sign for instance %s: %w", reserved.Instance.ID, err)
		}

		presented = append(presented, Selection{
			DocType:  disclosed.DocType,
			Document: *disclosed,
			Signer:   signer,
			// Which docRequest this answers. See Selection.QueryId: docType alone
			// cannot say, when a reader sent two docRequests for the same one.
			QueryId: selection.QueryId,
		})

		// Recorded for the activity log. Kept as the stored batch plus the request
		// facts rather than as a finished log entry, because rendering one needs
		// display metadata and a locale that belong to the client, not here --
		// this package answers a protocol and should not grow an opinion about how
		// a credential is shown to a person.
		w.disclosed = append(w.disclosed, DisclosedCredential{
			Batch:      reserved.Batch,
			ClaimPaths: selection.ClaimPaths,
			Claims:     claimsByQuery[selection.QueryId],
		})
	}

	return presented, nil
}

// Commit spends every instance this disclosure reserved.
//
// Called by Session only once the response is assembled and sealed, which is the
// first point at which nothing further can fail. Reserving and spending are
// separate for exactly that reason — see services.MdocInstanceSelector.Spend.
// reservedFor is one reserved instance and the credential query whose document
// it answers.
type reservedFor struct {
	queryID  string
	instance *services.ReservedInstance
}

// Commit spends the instances this disclosure reserved, except those whose
// documents left as zero-knowledge proofs.
//
// The asymmetry is the specification's, not a policy of ours: a plain ISO mdoc
// presentation SHALL consume its attestation, while "an attestation presented
// as a Zero-Knowledge Proof is not consumed and MAY be reused within its
// validity period". Spending on both paths would empty a thirty-attestation
// batch after thirty age checks and drop the wallet into the fallback it was
// proving to avoid — paying a scarce credential for privacy the proof had
// already provided. See Committer.
//
// What is kept is not released here. Release runs on every path out of
// Respond, including this one, and gives the claim back without marking the
// instance used, which is exactly what an unconsumed attestation needs.
func (w *WalletDiscloser) Commit(proved []string) error {
	if w.instances == nil {
		return nil
	}

	provedQueries := make(map[string]struct{}, len(proved))
	for _, queryID := range proved {
		provedQueries[queryID] = struct{}{}
	}

	spend := make([]*services.ReservedInstance, 0, len(w.reserved))
	keep := make([]reservedFor, 0, len(proved))
	for _, reservation := range w.reserved {
		if _, isProof := provedQueries[reservation.queryID]; isProof {
			keep = append(keep, reservation)
			continue
		}
		spend = append(spend, reservation.instance)
	}

	// Assigned before spending, so a SpendAll that fails halfway still leaves
	// Release the unconsumed set to hand back rather than the whole disclosure.
	w.reserved = keep

	return w.instances.SpendAll(spend)
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
	instances := make([]*services.ReservedInstance, 0, len(w.reserved))
	for _, reservation := range w.reserved {
		instances = append(instances, reservation.instance)
	}
	w.instances.Release(instances...)
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

// ============================================================
// READER AUTHORIZATION — what the certificate entitles it to ask
// ============================================================

// ReaderAuthorizer decides whether an authenticated reader is entitled to the
// document it asked for.
//
// Separated behind an interface because the answer lives in the Yivi scheme
// extension of the reader's certificate, and reading that means the scheme and
// OpenID4VP packages, which this one does not depend on and should not start
// depending on: an ISO 18013-5 transport has no business knowing how a
// relying-party registration is encoded. The client supplies the implementation
// it already uses for OpenID4VP, so both transports refuse the same requests
// for the same reason.
type ReaderAuthorizer interface {
	// AuthorizeReader returns nil when the certificate is entitled to request
	// docType with these element names, and an error describing the refusal
	// otherwise. Element names are the mdoc data element identifiers, which is
	// what the scheme's authorized sets are written in.
	AuthorizeReader(certificate *x509.Certificate, docType string, elements []string) error
}

// authorize holds every authenticated reader to its certificate's authorized
// attribute sets.
//
// This is the check that made a verifier's request fail online with "credential
// X is not in the authorized set", and without it the same reader gets what it
// asked for simply by arriving over the Digital Credentials API instead. The
// certificate is the same certificate and the entitlement is a property of the
// relying party, not of the transport it chose.
//
// Two deliberate limits:
//
//   - An UNAUTHENTICATED reader is not checked here. It presented no certificate,
//     so there is no authorized set to read, and what it may receive has already
//     been decided by ReleasableWithoutReaderAuth, which on this transport is
//     nothing at all. Refusing it here would report the wrong reason for a
//     request that has already been narrowed to empty.
//   - The check runs against Permitted rather than Requested. Requested is what
//     the reader asked for; Permitted is what it could receive after reader
//     authentication was weighed. Authorizing the larger set would refuse
//     requests that are about to be narrowed anyway.
//
// A refusal fails the session rather than dropping the document. The reader
// asked for something it is not registered to ask for, which is a
// misconfiguration or an attack, and answering it with a partial response would
// obscure both.
func (w *WalletDiscloser) authorize(documents []RequestedDocument) error {
	if w.authorizer == nil {
		return nil
	}

	for _, document := range documents {
		if document.Reader == nil || document.Reader.Certificate == nil {
			continue
		}

		elements := elementNames(document.Permitted)
		if len(elements) == 0 {
			continue
		}

		if err := w.authorizer.AuthorizeReader(
			document.Reader.Certificate, document.Permitted.DocType, elements,
		); err != nil {
			return fmt.Errorf("reader %q is not authorized for %s: %w",
				document.Reader.CommonName(), document.Permitted.DocType, err)
		}
	}
	return nil
}

// elementNames flattens an ItemsRequest to the data element identifiers the
// scheme's authorized sets are written in.
//
// Namespaces are flattened away, matching what the OpenID4VP path authorizes
// on: dcql.CredentialQuery.AuthorizationAttributeNames takes the last component
// of an mdoc claim path, which is the element name. Authorizing on a
// namespace-qualified name here would refuse every request the other transport
// allows.
func elementNames(items mdoc.ItemsRequest) []string {
	var names []string
	for _, elements := range items.NameSpaces {
		for element := range elements {
			names = append(names, element)
		}
	}
	slices.Sort(names)
	return names
}

// requireTrueThresholds constrains every claim of an Age Verification credential
// query to the value true, and reports whether it changed anything.
//
// Not a conformance tidy-up. An AV attestation carries a whole ladder --
// age_over_25 true, age_over_28 true, age_over_40 false -- and a proof over a
// false entry is a cryptographically certain statement that the holder is under
// that age. The soundness of the system guarantees it: the circuit binds the
// value to the digest the issuer signed, so a wallet cannot claim true over a
// signed false, but it CAN honestly prove false, and the relying party then
// learns something the attestation exists to withhold. The plain A.6 fallback is
// worse still, since the false travels under the full MSO and device signature.
//
// age_over_18 is included, on the same terms as every other threshold. AV Annex
// A A.4.2 makes it mandatory in issuance and defines it as indicating WHETHER
// the holder is over 18, not that they are, so a minor holds a conformant
// attestation carrying false -- and that holder is the one with most to lose
// from a proof of it. This does not weaken requireAgeVerificationBaseline, which
// refuses an attestation LACKING age_over_18 at issuance: the element must be
// there, and it must not travel when false.
//
// Expressed as a DCQL value constraint rather than as a filter over the
// candidates a search returned, and that distinction is the whole point. An
// earlier version dropped a claim only when EVERY candidate answered it false,
// reasoning that a claim one credential can answer honestly is still answerable.
// That is true of the claim and false of the credential: a wallet holding two AV
// attestations, one saying age_over_21 true and one saying false, kept the claim
// and left the false-answering credential in the selection set, so choosing it
// proved false after all. Constraining the value instead means such a credential
// never becomes a candidate, because claimMatches rejects it -- there is nothing
// left to choose wrongly. It is also DCQL's own vocabulary for "I want this
// element with this value", so the candidate search enforces it rather than a
// second mechanism downstream having to.
//
// Applied before the first search, so narrowing sees the constrained query: a
// request for [age_over_18, age_over_21] against a credential answering the
// second false matches no candidate at all (DCQL is all-or-nothing), 8.3.2.1.2.1
// narrowing then probes each claim and keeps the one answerable as true, and the
// reader gets age_over_18 with age_over_21 reported as an error. That is the
// same machinery that already answers a request naming an element the wallet
// does not hold, which is exactly what a false threshold now looks like.
//
// A claim the reader already constrained is left alone. A reader asking for
// age_over_18 = false is asking a question this wallet will simply not match,
// and rewriting its request to mean the opposite would be worse than refusing.
//
// Above zk/ on purpose: "age_over_NN must be true to be worth presenting" is AV
// profile semantics, and zk/ takes bytes and knows nothing of mdoc, CBOR or any
// profile. The ISO ItemsRequest has no field for a requested value -- its
// booleans are IntentToRetain -- so nothing upstream supplies this and the
// wallet must.
func requireTrueThresholds(query dcql.DcqlQuery) (dcql.DcqlQuery, bool) {
	constrained := query
	constrained.Credentials = make([]dcql.CredentialQuery, len(query.Credentials))
	copy(constrained.Credentials, query.Credentials)

	changed := false
	for i, credentialQuery := range query.Credentials {
		if credentialQuery.Meta == nil || credentialQuery.Meta.DocTypeValue != mdoc.AgeVerificationDocType {
			continue
		}

		claims := make([]dcql.Claim, len(credentialQuery.Claims))
		copy(claims, credentialQuery.Claims)
		for j := range claims {
			if len(claims[j].Values) > 0 {
				continue
			}
			claims[j].Values = []any{true}
			changed = true
		}
		constrained.Credentials[i].Claims = claims
	}

	return constrained, changed
}
