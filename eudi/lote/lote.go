// Package lote implements the recognized-list channel of the trust ladder: the
// list of trusted entities (a LoTE) that Yivi publishes, and against which a
// party can be granted the medium rung.
//
// The list is a JSON document in the shape of ETSI TS 119 602 — a scheme
// header (identifier, sequence number, next update) plus trust service
// providers, each offering role-typed services — signed as a compact
// JAdES-B-B: a single-signature JWS whose `x5c` chain verifies against the
// anchors pinned for that list. Trust as an issuer and trust as a verifier are
// separate grants, so the role is part of the entry rather than of the party.
//
// A list is usable only while all three of these hold:
//
//   - its signature verifies against the list's pinned anchors,
//   - the current time is before its `nextUpdate`,
//   - its sequence number does not regress below the copy already stored.
//
// Degradation is fail-soft, in one direction: a list that is unreachable,
// tampered with, expired or regressed is *absent* list evidence rather than an
// error. Nothing in this package can fail a session — the party simply lands on
// whatever rung the other channels give it, which is low when the certificate
// channel has nothing to say either.
package lote

import (
	"time"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// Yivi's profile of the list format pins the values below. They live here
// rather than being spread over the parser so that the profile settling on
// different ones is a one-place change.
const (
	// Typ is the value the signed list's JWS protected header must carry. A
	// JWS with any other `typ` is not a trust list and is rejected before its
	// signature is even checked.
	Typ = "lote+jwt"

	// ServiceTypeIssuer types an entry as trust in the party's capacity to
	// issue credentials.
	ServiceTypeIssuer = "https://yivi.app/trustlist/svctype/credential-issuer"
	// ServiceTypeVerifier types an entry as trust in the party's capacity to
	// verify them.
	ServiceTypeVerifier = "https://yivi.app/trustlist/svctype/relying-party"

	// StatusGranted is the only service status that vouches for a party; these
	// two are the ETSI TS 119 612 status URIs.
	StatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	// StatusWithdrawn marks a party whose grant was taken away. A withdrawn
	// entry vouches for nothing, exactly like an absent one.
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"

	// QualifierOnboardedByYivi marks an entry Yivi itself vouches for. It is
	// parsed and carried on the listing here, but nothing ranks on it yet: the
	// marking lifts an entry to high only on Yivi's own list, which is the
	// slice that adds the rung.
	QualifierOnboardedByYivi = "https://yivi.app/trustlist/qualifier/onboarded-by-yivi"
)

// The OtherId conventions. A digital identity that is not a certificate names
// the identifier space it lives in, and carries the identifier verbatim as the
// protocol hands it to the wallet — so an entry is matched by string equality
// against the party's identifiers, with no per-space normalisation to get
// wrong.
const (
	// OtherIdTypeDid is a DID, spelled exactly as the DID document is
	// resolved: "did:web:verifier.example.com", never the OpenID4VP
	// `decentralized_identifier:` client_id framing around it.
	OtherIdTypeDid = "did"
	// OtherIdTypeUri is an HTTPS identifier, such as an OpenID4VCI credential
	// issuer identifier, without a trailing slash.
	OtherIdTypeUri = "uri"
)

// Fetch bounds. The list is a few tens of kilobytes of JSON; the cap is there
// so a hostile endpoint cannot stream the wallet out of memory.
const (
	fetchTimeout = 10 * time.Second
	maxBodyBytes = 2 * 1024 * 1024

	// fetchBackoff is how long a list is left alone after an attempt to fetch
	// it. Without it every session of a wallet whose list endpoint is down
	// would wait out the fetch timeout again.
	fetchBackoff = time.Minute
)

// RecognizedList is one list the wallet recognizes, and everything it takes to
// decide whether a copy of that list is genuine.
type RecognizedList struct {
	// Id is the list's identifier. A fetched list must carry it as its own
	// `listIdentifier`, so serving list B's content at list A's URL does not
	// grant B's entries A's recognition.
	Id string

	// URL is where the signed list is fetched from.
	URL string

	// Anchors verify the chain of the certificate the list is signed with. Each
	// list brings its own: recognizing a list is exactly the decision to
	// believe what one signer says about other parties.
	Anchors eudi_jwt.X509VerificationContext
}
