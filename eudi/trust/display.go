package trust

import "github.com/privacybydesign/irmago/common/clientmodels"

// PartyMetadata is one source's account of who a party is, resolved for the
// locale in use.
type PartyMetadata struct {
	// Name is the party's display name, or "" when this source does not name it.
	Name string
	// Logo is the logo this source carries, or nil when it carries none.
	Logo *clientmodels.Image
}

// PartyDisplay is everything a protocol path has to present one party with,
// grouped by how strongly curated it is. [PartyDisplay.TrustedParty] reduces it
// to the party the app renders.
//
// Both protocol paths compose their parties through this one type, so the
// precedence rules cannot drift apart between a disclosure and an issuance:
// what the party says about itself never outranks what somebody vouching for it
// says, and a logo is never the party's own word.
type PartyDisplay struct {
	// Id is the party's stable identifier: the certificate serial number, the
	// credential issuer URL, the verifier's DID. It is always reported, and at
	// low it is the only thing on the screen the party did not choose itself,
	// which is why the app shows it alongside the name there.
	Id string

	// Attested is what the party's validated certificate says about it.
	//
	// Supply this only when the party actually authenticated with a certificate
	// that verified against the Yivi anchors — the same condition that puts a
	// non-nil Certificate in its [Evidence]. It is a vouched-for source, so its
	// logo is rendered; a name the party merely asserted belongs in
	// SelfAssertedName however it reached the wallet, and a logo it merely
	// asserted goes nowhere.
	Attested PartyMetadata

	// SelfAssertedName is what the party calls itself: OpenID4VP client
	// metadata, an issuer's own credential-issuer metadata, a hostname read off
	// its response URI. It is the last resort, shown under the warn state for
	// the user to judge.
	//
	// There is no self-asserted logo, by design. A name the party chose is a
	// claim the user can weigh against the warning next to it; a logo is not
	// weighed at all, it is simply believed, so nothing the party says about
	// itself may supply one and there is nowhere here to put it.
	SelfAssertedName string

	// CuratedLogo is the logo the recognized-list entry names, already loaded.
	// The curated *name* comes off the verdict's [Listing]; the logo cannot,
	// because resolving its URI goes through the wallet's logo cache and this
	// package knows nothing about storage.
	CuratedLogo *clientmodels.Image
}

// TrustedParty composes the party the app renders, resolving name and logo by
// curation strength: the curated list entry first, the certificate second, and
// what the party says about itself last.
//
// A logo is only ever taken from a source beyond the party — a listing or a
// certificate. A self-asserted name shown under the warn state is the user's to
// judge, but a logo is the whole of an impersonation, so nothing the party
// merely claims about itself can supply one. At low no other source exists by
// construction (no certificate authenticated the party and no list vouched for
// it), so low renders the self-asserted name, the identifier, and no logo.
func (d PartyDisplay) TrustedParty(verdict Verdict, locale string) *clientmodels.TrustedParty {
	party := &clientmodels.TrustedParty{
		Id:         d.Id,
		TrustLevel: verdict.Level,
	}

	var curatedName string
	if verdict.Listing != nil {
		curatedName = clientmodels.Resolve(verdict.Listing.Name, locale)
	}

	switch {
	case curatedName != "":
		party.Name = curatedName
	case d.Attested.Name != "":
		party.Name = d.Attested.Name
	default:
		party.Name = d.SelfAssertedName
	}

	switch {
	case verdict.Listing != nil && d.CuratedLogo != nil:
		party.Image = d.CuratedLogo
	case d.Attested.Logo != nil:
		party.Image = d.Attested.Logo
	}

	return party
}
