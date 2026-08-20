package trust

import "github.com/privacybydesign/irmago/common/clientmodels"

// PartyMetadata is one source's account of who a party is, resolved for the
// locale in use.
type PartyMetadata struct {
	Name string
	Logo *clientmodels.Image
}

// PartyDisplay is everything a protocol path has to present one party with,
// grouped by how strongly curated it is. [PartyDisplay.TrustedParty] reduces it
// to the party the app renders. Both protocols compose through it, so a
// disclosure and an issuance cannot drift apart on precedence.
type PartyDisplay struct {
	// Id is the party's stable identifier: the certificate serial number, the
	// credential issuer URL, the verifier's DID. Always reported, and at low the
	// only thing on the screen the party did not choose itself.
	Id string

	// Attested is what the party's certificate says about it, when an anchor the
	// wallet holds stands behind that certificate — and only then, since the
	// contents of an unanchored certificate are evidentially the party's own word.
	// Its logo is rendered; a name the party merely asserted belongs in
	// SelfAssertedName however it reached the wallet.
	Attested PartyMetadata

	// SelfAssertedName is what the party calls itself: OpenID4VP client metadata,
	// credential-issuer metadata, a hostname off its response URI. The last
	// resort, shown under the warn state for the user to judge.
	//
	// There is no self-asserted logo, by design: a name the user can weigh against
	// the warning next to it, a logo is simply believed.
	SelfAssertedName string

	// CuratedLogo is the logo the recognized-list entry names, already loaded. The
	// curated name comes off the verdict's [Listing]; the logo cannot, since
	// resolving its URI goes through the wallet's logo cache.
	CuratedLogo *clientmodels.Image
}

// TrustedParty composes the party the app renders, resolving name and logo by
// curation strength: the curated list entry first, the certificate second, what
// the party says about itself last.
//
// A logo is only ever taken from a source beyond the party, because a logo is the
// whole of an impersonation. At low no such source exists by construction, so low
// renders the self-asserted name, the identifier, and no logo.
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
