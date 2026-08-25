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

// snapshot is an immutable set of current lists, answering the same way for a
// whole session however many refreshes land meanwhile.
type snapshot struct {
	lists []pinnedList
}

// Lookup implements [trust.ListSnapshot]: the strongest granting entry across the
// lists, since a party granted on two must get the better of the two words. Within
// one list the first granting entry stands, every entry conferring the same level,
// and ties go to configuration order.
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

func grants(entity *Entity, service *Service, role trust.Role, ev trust.Evidence) bool {
	info := &service.Information
	if !info.IsGranted() {
		return false
	}
	// An unrecognized service type maps to no role and so matches nothing.
	granted, ok := info.Type.Role()
	if !ok || granted != role {
		return false
	}
	return matchesIdentity(entity, service, ev)
}

// matchesIdentity checks the party against the service's digital identities. A
// party may carry two handles onto its identity — the certificate (plus the legal
// entity, when the entry names one) and an identifier such as a DID or issuer URL
// — and an entry granting either grants the party.
//
// A union, because a DID party that also carries an attesting certificate has
// both handles genuinely, and keying on the certificate's presence would drop its
// DID-keyed listing the moment it attested. Judged independently, so the
// organization-identifier cross-check is never rescued by the other handle.
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
// OtherId entry. An OtherId is a bare string in Annex A, compared verbatim. An
// empty entry would match an empty identifier, so it is skipped.
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

// matchesCertificate checks the party's certificate against every certificate and
// key the entry names; any one of them matching is enough.
func matchesCertificate(identity *DigitalIdentity, cert *x509.Certificate) bool {
	for _, listed := range identity.X509Certificates {
		if len(listed.Val) > 0 && bytes.Equal(listed.Val, cert.Raw) {
			return true
		}
	}
	// An entry keyed on the subject key identifier keeps granting across a renewal
	// that reuses the key.
	for _, ski := range identity.X509SKIs {
		if len(ski) > 0 && bytes.Equal(ski, cert.SubjectKeyId) {
			return true
		}
	}
	return false
}

// listingOf builds the entry the verdict reports, resolving the service's
// overrides over what the entity says.
func listingOf(pinned pinnedList, entity *Entity, service *Service) *trust.Listing {
	// ServiceName is mandatory in Annex A, so it is normally set. The fallback is
	// for a document that omits it anyway.
	name := service.Information.Name
	if len(name) == 0 {
		name = entity.Information.Name
	}
	logoURI := service.Information.LogoURI()
	if logoURI == "" {
		logoURI = entity.Information.LogoURI()
	}
	return &trust.Listing{
		ListId:  pinned.source.Key,
		Name:    name.Translated(),
		LogoURI: logoURI,
		Level:   pinned.source.Confers,
	}
}
