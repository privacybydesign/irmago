package lote

import (
	"bytes"
	"crypto/x509"
	"slices"

	"github.com/privacybydesign/irmago/eudi/trust"
)

// pinnedList is one current list together with the source it came from, which
// is what says whether its markings are Yivi's own word.
type pinnedList struct {
	source Source
	list   *List
}

// snapshot is an immutable set of current lists. It is handed to a session and
// answers the same way for the whole of it, however many refreshes land in the
// meantime.
type snapshot struct {
	lists []pinnedList
}

// Lookup implements [trust.ListSnapshot]. It returns the strongest granting
// entry across the lists — the rung a listing confers is its source's, so a
// party granted on two lists must get the better of the two words, whatever
// order the sources were configured in. Within one list the first granting
// entry stands: every entry on a list confers the same level.
//
// Ties go to configuration order, which keeps the answer deterministic when
// two equally-strong lists both grant.
func (s snapshot) Lookup(role trust.Role, ev trust.Evidence) *trust.Listing {
	var best *trust.Listing
	for _, pinned := range s.lists {
		listing := pinned.lookup(role, ev)
		if listing == nil {
			continue
		}
		if best == nil || trust.Stronger(listing.Level, best.Level) {
			best = listing
		}
	}
	return best
}

// lookup returns the first entry on this list granting the party in this role,
// or nil when none does.
func (p pinnedList) lookup(role trust.Role, ev trust.Evidence) *trust.Listing {
	for i := range p.list.Entities {
		entity := &p.list.Entities[i]
		for j := range entity.Services {
			service := &entity.Services[j]
			if grants(entity, service, role, ev) {
				return listingOf(p, entity, service)
			}
		}
	}
	return nil
}

// grants reports whether this service is a live grant of this role to the party
// the evidence describes.
func grants(entity *Entity, service *Service, role trust.Role, ev trust.Evidence) bool {
	info := &service.Information
	if !info.IsGranted() {
		return false
	}
	// An entry whose service type is not one of the ladder's roles matches
	// nothing: an unrecognized type URI maps to no role, and the caller only
	// ever asks about a real one.
	granted, ok := info.Type.Role()
	if !ok || granted != role {
		return false
	}
	return matchesIdentity(entity, service, ev)
}

// matchesIdentity checks the party against the service's digital identities.
//
// A party may carry two handles onto its identity, and an entry granting
// either one grants the party. The certificate handle is the whole certificate
// or the key it carries, AND the legal entity when the entry names one. The
// identifier handle is a DID or issuer URL against the OtherId entries.
//
// The two are a union because a DID party that also carries an attesting
// certificate has both handles genuinely — the certificate vouches for the key
// it authenticated with, it is not how it authenticated. Keying only on
// whether a certificate is present would drop such a party's DID-keyed listing
// the moment it attested. The handles are judged independently rather than in
// sequence, so the certificate handle's organization-identifier cross-check is
// never rescued by the identifier handle: a reassigned key still fails.
func matchesIdentity(entity *Entity, service *Service, ev trust.Evidence) bool {
	return matchesCertificateHandle(entity, service, ev) ||
		matchesIdentifierHandle(service, ev)
}

// matchesCertificateHandle grants when the party's certificate matches an entry
// certificate or key AND the entry's organization identifier matches (or the
// entry names none). Both halves are required: the certificate says which key
// signed, the organization identifier says whose key it is, and an entry that
// pinned only the key would keep granting the entity that key was reassigned to.
func matchesCertificateHandle(entity *Entity, service *Service, ev trust.Evidence) bool {
	if ev.Certificate == nil {
		return false
	}
	if !matchesCertificate(&service.Information.DigitalIdentity, ev.Certificate) {
		return false
	}
	organizationIdentifier := entity.Information.OrganizationIdentifier()
	if organizationIdentifier == "" {
		return true
	}
	return organizationIdentifier == CertificateOrganizationIdentifier(ev.Certificate)
}

// matchesIdentifierHandle grants when one of the party's identifiers matches an
// OtherId entry. An OtherId is a bare string in Annex A, so there is no type to
// filter on: a DID or issuer URL is self-describing and compared verbatim. An
// empty entry would match an empty identifier, so it is skipped rather than
// trusted.
func matchesIdentifierHandle(service *Service, ev trust.Evidence) bool {
	for _, other := range service.Information.DigitalIdentity.OtherIds {
		if other == "" {
			continue
		}
		if slices.Contains(ev.Identifiers, other) {
			return true
		}
	}
	return false
}

// matchesCertificate checks the party's certificate against every certificate
// and key the entry names. The binding makes both members sequences, so one
// service may be recognized by several certificates or keys and any one of them
// matching is enough.
func matchesCertificate(identity *DigitalIdentity, cert *x509.Certificate) bool {
	for _, listed := range identity.X509Certificates {
		if len(listed.Val) > 0 && bytes.Equal(listed.Val, cert.Raw) {
			return true
		}
	}
	// An entry keyed on the subject key identifier keeps granting across a
	// certificate renewal that reuses the key, which is why a scheme operator
	// would use it instead of pinning the certificate.
	for _, ski := range identity.X509SKIs {
		if len(ski) > 0 && bytes.Equal(ski, cert.SubjectKeyId) {
			return true
		}
	}
	return false
}

// listingOf builds the entry the verdict reports, resolving what the service
// overrides over what the entity says.
func listingOf(pinned pinnedList, entity *Entity, service *Service) *trust.Listing {
	// ServiceName is mandatory in Annex A, so unlike the optional override it
	// replaces it is normally set — a service not presented under its own brand
	// simply repeats the entity's name. The fallback stays for a document that
	// omits it anyway: an unnamed listing should still show who it is.
	name := service.Information.Name
	if len(name) == 0 {
		name = entity.Information.Name
	}
	logoURI := service.Information.LogoURI()
	if logoURI == "" {
		logoURI = entity.Information.LogoURI()
	}
	return &trust.Listing{
		ListId:  pinned.source.ListId,
		Name:    name.Translated(),
		LogoURI: logoURI,
		Level:   pinned.source.Confers,
	}
}
