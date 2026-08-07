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

// Lookup implements [trust.ListSnapshot]. It returns the first granting entry
// found, searching the lists in configuration order.
//
// "First" is enough because being granted is all the caller asks about: the
// rung a listing earns does not depend on which list it was found on, except
// for the onboarded-by-Yivi marking, which only Yivi's own list can carry in
// the first place.
func (s snapshot) Lookup(role trust.Role, ev trust.Evidence) *trust.Listing {
	for _, pinned := range s.lists {
		for i := range pinned.list.Entities {
			entity := &pinned.list.Entities[i]
			for j := range entity.Services {
				service := &entity.Services[j]
				if !grants(entity, service, role, ev) {
					continue
				}
				return listingOf(pinned, entity, service)
			}
		}
	}
	return nil
}

// grants reports whether this service is a live grant of this role to the party
// the evidence describes.
func grants(entity *Entity, service *Service, role trust.Role, ev trust.Evidence) bool {
	if service.Status != ServiceStatusGranted {
		return false
	}
	// An entry whose type is not one of the ladder's roles matches nothing: the
	// caller only ever asks about a real role, so an unknown wire value cannot
	// equal it.
	if service.Type != role {
		return false
	}
	return matchesIdentity(entity, service, ev)
}

// matchesIdentity checks the party against the service's digital identities.
//
// A certificate-bearing party is matched on the certificate — the whole
// certificate or the key it carries — AND on the legal entity, when the entry
// names one. Both halves are required: the certificate says which key signed,
// the organization identifier says whose key it is, and an entry that pinned
// only the key would keep granting the entity that key was reassigned to.
//
// A party without a certificate is matched on its identifiers, against the
// OtherId entries. Nothing is inferred across the two: a DID entry does not
// grant a certificate-bearing party and vice versa.
func matchesIdentity(entity *Entity, service *Service, ev trust.Evidence) bool {
	identity := &service.DigitalIdentity

	if ev.Certificate != nil {
		if !matchesCertificate(identity, ev.Certificate) {
			return false
		}
		if entity.OrganizationIdentifier == "" {
			return true
		}
		return entity.OrganizationIdentifier == certificateOrganizationIdentifier(ev.Certificate)
	}

	for _, other := range identity.OtherIds {
		if other.Type != OtherIdTypeDid || other.Value == "" {
			continue
		}
		if slices.Contains(ev.Identifiers, other.Value) {
			return true
		}
	}
	return false
}

func matchesCertificate(identity *DigitalIdentity, cert *x509.Certificate) bool {
	if len(identity.X509Certificate) > 0 && bytes.Equal(identity.X509Certificate, cert.Raw) {
		return true
	}
	// An entry keyed on the subject key identifier keeps granting across a
	// certificate renewal that reuses the key, which is why a scheme operator
	// would use it instead of pinning the certificate.
	return len(identity.X509SKI) > 0 && bytes.Equal(identity.X509SKI, cert.SubjectKeyId)
}

// listingOf builds the entry the verdict reports, resolving what the service
// overrides over what the entity says.
func listingOf(pinned pinnedList, entity *Entity, service *Service) *trust.Listing {
	name := service.Name
	if len(name) == 0 {
		name = entity.Name
	}
	logoURI := service.LogoURI
	if logoURI == "" {
		logoURI = entity.LogoURI
	}
	return &trust.Listing{
		ListId:  pinned.source.ListId,
		Name:    name,
		LogoURI: logoURI,
		// Yivi vouching for a party is Yivi's statement to make. The same
		// marking on another operator's list is that operator claiming Yivi
		// onboarded someone, so it is not carried through.
		OnboardedByYivi: pinned.source.OperatedByYivi && service.HasMarking(MarkingOnboardedByYivi),
	}
}
