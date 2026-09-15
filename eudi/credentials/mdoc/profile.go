package mdoc

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// DOCUMENT PROFILES
//
// ISO/IEC 18013-5 defines the format. A profile is the set of extra rules one
// docType layers on top of it — which attributes may appear, whether the holder
// may assert anything of its own, how the validity window is stamped.
//
// This file is the only place in the package that knows a profile by name.
// Everything outside it is general mso_mdoc and has to stay that way: a rule
// enforced against every docType because one profile requires it rejects
// conformant documents of every other type, and does so in a way that looks
// like a signature or trust failure rather than a policy decision. That is not
// hypothetical — the device-signed-namespaces refusal below was applied to all
// docTypes for exactly that reason before this file existed.
// ============================================================

// AgeVerificationDocType and AgeVerificationNameSpace identify the EUDI Age
// Verification profile, which uses the same string for both.
//
// Source: the AV Blueprint's architecture and technical specification
// (ageverification.dev). Note this is the mdoc docType, not the OpenID4VCI
// credential configuration id — the reference issuer advertises the latter as
// "eu.europa.ec.eudi.age_verification_mdoc" while minting documents whose
// docType is this. Profile dispatch keys off the docType inside the signed MSO,
// so the configuration id never reaches here.
const (
	AgeVerificationDocType   = "eu.europa.ec.av.1"
	AgeVerificationNameSpace = "eu.europa.ec.av.1"
)

// avAgeOverElement matches the only attribute family the AV profile permits.
//
// Deliberately duplicated from services.mdocAgeOverElement rather than shared:
// services imports this package, so the dependency cannot run the other way,
// and that copy answers a display question ("can this element be given a
// human-readable name") where this one answers a conformance question ("may
// this element appear at all"). They agree today and are free to diverge.
var avAgeOverElement = regexp.MustCompile(`^age_over_[0-9]{1,2}$`)

// documentProfile is the rule set for one docType. The zero-value-ish general
// profile returned by profileFor is plain ISO/IEC 18013-5 with nothing added.
type documentProfile struct {
	// docType is the profile's own identifier, or the document's docType when no
	// profile is known for it.
	docType string

	// name is what appears in a rejection, so an operator can tell a profile rule
	// apart from a format rule.
	name string

	// holderMayAssertClaims reports whether DeviceSigned.NameSpaces may carry
	// anything at all.
	//
	// ISO/IEC 18013-5 9.1.3.4 permits holder-asserted elements generally, subject
	// to the KeyAuthorizations check in checkDeviceSignedNameSpaces. A profile
	// with no holder-asserted attributes sets this false, which refuses them
	// outright — a stricter rule that only that profile is entitled to apply.
	holderMayAssertClaims bool

	// permittedElement, when non-nil, is the profile's closed attribute set. Nil
	// means open: 18013-5 places no restriction on element identifiers, and a
	// docType this package has never heard of must not have one invented for it.
	permittedElement func(elementIdentifier string) bool

	// coarsenValidityTimestamps truncates the ValidityInfo timestamps to midnight
	// UTC at issuance.
	//
	// 9.1.2.4 recommends this generally ("should set these timestamps with a
	// precision that limits the linkability information"), so it is on by default
	// rather than being an AV artifact. The AV Blueprint promotes it to a SHALL:
	// "An Attestation Provider SHALL set the timestamp included in the
	// ValidityInfo structure with a precision that limits the linkability
	// information."
	//
	// Consequence worth knowing before changing it: coarsening puts `signed`
	// hours before the document signer's NotBefore, which is why 9.3.1 step 5's
	// first bullet cannot be enforced until DS certificates are issued with a
	// backdated NotBefore.
	coarsenValidityTimestamps bool

	// validityPeriod is how long an issued credential stays valid. 18013-5 sets
	// no bound; the AV Blueprint recommends "a maximum period of three (3) months
	// from the date of issuance".
	validityPeriod time.Duration
}

// profileFor returns the rules that apply to docType. An unrecognised docType
// gets general ISO/IEC 18013-5 and nothing more, which is the whole point: this
// package targets mso_mdoc, and AV is one profile on top of it.
func profileFor(docType string) documentProfile {
	switch docType {
	case AgeVerificationDocType:
		return documentProfile{
			docType: AgeVerificationDocType,
			name:    "EUDI Age Verification",
			// "A Proof of Age Attestation SHALL NOT include any other attribute" —
			// age_over_18 mandatory, age_over_NN optional, nothing else. There are
			// therefore no holder-asserted attributes either.
			holderMayAssertClaims:     false,
			permittedElement:          avAgeOverElement.MatchString,
			coarsenValidityTimestamps: true,
			validityPeriod:            90 * 24 * time.Hour, // "maximum period of three (3) months"
		}
	default:
		return documentProfile{
			docType:                   docType,
			name:                      "ISO/IEC 18013-5",
			holderMayAssertClaims:     true,
			permittedElement:          nil,
			coarsenValidityTimestamps: true, // 9.1.2.4's recommendation, not a profile rule
			validityPeriod:            90 * 24 * time.Hour,
		}
	}
}

// checkElements enforces a profile's closed attribute set over the elements a
// document actually disclosed, keyed namespace -> elementIdentifier -> value.
//
// Only a profile that defines one is checked. For every other docType this is a
// no-op, because 18013-5 itself says nothing about which element identifiers may
// appear and inventing a restriction would reject conformant documents.
func (p documentProfile) checkElements(resolved map[string]map[string]any) error {
	if p.permittedElement == nil {
		return nil
	}
	var offending []string
	for namespace, attrs := range resolved {
		for elementIdentifier := range attrs {
			if !p.permittedElement(elementIdentifier) {
				offending = append(offending, namespace+"/"+elementIdentifier)
			}
		}
	}
	if len(offending) == 0 {
		return nil
	}
	slices.Sort(offending)
	return fmt.Errorf(
		"docType %s follows the %s profile, which permits only age_over_NN attributes, but the document discloses %s",
		p.docType, p.name, strings.Join(offending, ", "))
}

// checkDeviceSignedNameSpaces decides whether the holder-asserted elements in a
// presentation are acceptable. Called only after the device signature over them
// has verified — a rule enforced on unauthenticated bytes proves nothing about
// the holder.
//
// Two different rules, and which applies is the whole reason this file exists:
//
//   - A profile with no holder-asserted attributes refuses any. Nothing signed
//     them but the holder, and callers read VerificationResult.Attributes without
//     being able to tell issuer-attested values from self-asserted ones.
//
//   - Every other docType gets ISO/IEC 18013-5 9.1.3.4: "An mdoc shall only
//     authenticate response data elements in DeviceNameSpaces if the key it is
//     using for mdoc authentication is authorized to authenticate these elements
//     in the KeyAuthorizations structure in the MSO. The mdoc reader shall
//     validate this authorization as part of validating the mdoc authentication."
//     So the elements are permitted exactly to the extent the issuer authorized
//     the device key to assert them.
func (p documentProfile) checkDeviceSignedNameSpaces(
	deviceNameSpaces map[string]map[string]cbor.RawMessage,
	authorizations *KeyAuthorizations,
) error {
	if len(deviceNameSpaces) == 0 {
		return nil
	}

	if !p.holderMayAssertClaims {
		namespaces := make([]string, 0, len(deviceNameSpaces))
		for ns := range deviceNameSpaces {
			namespaces = append(namespaces, ns)
		}
		slices.Sort(namespaces)
		return fmt.Errorf(
			"docType %s follows the %s profile, which has no holder-asserted attributes: the deviceAuth "+
				"signature is valid, but the document asserts %d holder-signed namespace(s) %v, which carry "+
				"no issuer attestation",
			p.docType, p.name, len(namespaces), namespaces)
	}

	// 9.1.2.4: "If the KeyAuthorizations map is present, it shall not be empty."
	// Absent means the issuer authorized the device key to assert nothing.
	if authorizations == nil || authorizations.isEmpty() {
		return fmt.Errorf(
			"document asserts holder-signed elements, but the MSO's deviceKeyInfo carries no keyAuthorizations: "+
				"ISO/IEC 18013-5 9.1.3.4 authorizes the device key to assert only what that structure names "+
				"(docType %s)", p.docType)
	}

	for namespace, elements := range deviceNameSpaces {
		// "If authorization is given for a full namespace (by including the
		// namespace in the AuthorizedNameSpaces array), that namespace shall not be
		// included in the AuthorizedDataElements map" — so a whole-namespace grant
		// settles every element under it.
		if slices.Contains(authorizations.NameSpaces, namespace) {
			continue
		}
		authorized := authorizations.DataElements[namespace]
		var unauthorized []string
		for elementIdentifier := range elements {
			if !slices.Contains(authorized, elementIdentifier) {
				unauthorized = append(unauthorized, elementIdentifier)
			}
		}
		if len(unauthorized) > 0 {
			slices.Sort(unauthorized)
			return fmt.Errorf(
				"the device key is not authorized to assert %s in namespace %s: the MSO's keyAuthorizations "+
					"names neither the namespace nor those elements (ISO/IEC 18013-5 9.1.3.4)",
				strings.Join(unauthorized, ", "), namespace)
		}
	}
	return nil
}

// issuedValidityInfo builds the ValidityInfo for a credential issued now under
// this profile, keeping the timestamp policy beside the rules that motivate it
// rather than inline in the issuer.
func (p documentProfile) issuedValidityInfo(now time.Time) ValidityInfo {
	now = now.UTC()
	if p.coarsenValidityTimestamps {
		// Truncating downwards rather than rounding keeps validFrom in the past, so
		// a credential is never briefly not-yet-valid against a verifier whose clock
		// trails ours.
		now = now.Truncate(24 * time.Hour)
	}
	return ValidityInfo{
		Signed:     now,
		ValidFrom:  now,
		ValidUntil: now.Add(p.validityPeriod),
	}
}
