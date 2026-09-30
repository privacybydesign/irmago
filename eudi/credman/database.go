// Package credman builds the credential database that Android's Credential
// Manager hands to a wallet's matcher.
//
// # What this is, and what it is not
//
// Registering a wallet as a Digital Credentials API provider on Android is a
// push: the app hands the platform (a) a WebAssembly matcher and (b) a CBOR
// database of everything it holds, and the platform runs the matcher against
// that database — inside its own process, with the wallet not running — to
// decide whether the wallet appears in the picker at all. Nothing in this
// package talks to the platform; it produces the bytes the Android layer
// registers, so the shape can be tested here rather than on a phone.
//
// This is NOT a wire format of any specification. It is the private contract
// between a matcher binary and the app that ships it. Ours is the matcher from
// the Multipaz project (Apache-2.0), vendored as a prebuilt .wasm, so the
// contract is whatever its CredentialDatabase.cpp parses — reproduced below,
// because nothing else documents it.
//
// # The contract
//
//	{ "protocols":   [tstr],             ; required, the DC API protocols offered
//	  "credentials": [                   ; required
//	    { "title":     tstr,             ; required
//	      "subtitle":  tstr,             ; required
//	      "bitmap":    bstr,             ; required, may be empty
//	      "protocols": [tstr],           ; optional, overrides the top-level list
//	      "mdoc": {                      ; optional (an sdjwt sibling also exists)
//	        "documentId": tstr,
//	        "docType":    tstr,
//	        "namespaces": { tstr => { tstr => [tstr, tstr, tstr] } }
//	      } } ] }
//
// The three-element array is [displayName, value, matchValue]: what the picker
// labels the field, what it shows as the value, and the raw form DCQL value
// constraints compare against. This package fills the first and deliberately
// leaves the other two empty — the picker draws them before the wallet has asked
// for a PIN, so a value there is published to anyone holding the phone. See
// renderElement for the argument.
//
// Every key marked required really is: the matcher dereferences the result of
// its map lookup without a nil check, so an absent "bitmap" is not a missing
// field, it is a crash inside the platform's WASM runtime, observed by the user
// as a wallet that silently never appears. Hence [][]byte{} rather than nil for
// an absent image, and hence this package emitting every required key
// unconditionally.
//
// # Why the claims are flattened to namespace.element
//
// The matcher joins a DCQL claim path with "." and looks the result up in one
// flat map (dcql.h joinPath, CredentialDatabase.cpp). An mdoc DCQL path is
// always [namespace, element], so "namespace.element" is the whole key space
// for this format, and it maps one-to-one onto models.MdocNamespaces. That is
// why this builds from the stored namespaces directly rather than from
// services.BuildMdocAttributes, whose flattened deep paths and promoted data
// URIs have nowhere to go in a two-level model.
package credman

import (
	"fmt"
	"sort"

	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// ProtocolIsoMdoc is the Digital Credentials API protocol identifier for ISO/IEC
// 18013-5's own request and response, which is the one the EUDI Age Verification
// profile pairs zero-knowledge presentation with.
//
// Duplicated from eudi/isomdoc rather than imported: this package describes an
// Android registry entry, not the protocol, and the two are pinned together by a
// test.
const ProtocolIsoMdoc = "org-iso-mdoc"

// encMode sorts map keys canonically. The Android layer skips re-registration
// when the database digest is unchanged, so an encoder whose map order drifted
// between calls would re-push the whole database on every credential event and
// make the skip useless.
var encMode, _ = cbor.EncOptions{Sort: cbor.SortCanonical}.EncMode()

// database is the top-level document.
type database struct {
	Protocols   []string     `cbor:"protocols"`
	Credentials []credential `cbor:"credentials"`
}

// credential is one entry in the picker.
type credential struct {
	Title    string `cbor:"title"`
	Subtitle string `cbor:"subtitle"`

	// Bitmap is the picker's thumbnail. Always present, empty for now: the
	// matcher requires the key, and resizing card art is work that buys only a
	// nicer row. Kept as a field so adding it later is not a format change.
	Bitmap []byte `cbor:"bitmap"`

	// Protocols narrows the top-level offer for this credential alone. Omitted
	// while every credential is offered on the same protocols; present in the
	// contract because that stops being true as soon as one format is offered
	// over a protocol another cannot answer.
	Protocols []string `cbor:"protocols,omitempty"`

	Mdoc *mdocEntry `cbor:"mdoc,omitempty"`
}

type mdocEntry struct {
	// DocumentId is how the picker's selection names the credential back to us:
	// the matcher builds an entry id of "<combination> <protocol> <documentId>"
	// and the presentation activity splits it on spaces. See Build for what that
	// forbids.
	DocumentId string `cbor:"documentId"`
	DocType    string `cbor:"docType"`

	// Namespaces is namespace => element => [displayName, value, matchValue].
	Namespaces map[string]map[string][3]string `cbor:"namespaces"`
}

// Build encodes the credential database for the given stored mdoc batches.
//
// protocols is the set of DC API protocol identifiers to offer; a credential
// only matches a request whose protocol is in this list, so an empty list
// produces a database that can never match anything and is refused.
//
// locale resolves the display text. It is the app's current locale, and the
// database is rebuilt when that changes, because these strings are what the user
// reads in a picker rendered by the platform and not by us.
func Build(batches []*models.MdocBatch, locale string, protocols []string) ([]byte, error) {
	if len(protocols) == 0 {
		return nil, fmt.Errorf("credential database needs at least one protocol")
	}

	// Sorted so the same wallet contents always produce the same bytes. The
	// store returns batches in whatever order the query yielded, and an
	// unstable order would change the digest the Android layer dedupes on
	// without anything about the wallet having changed.
	sorted := make([]*models.MdocBatch, 0, len(batches))
	sorted = append(sorted, batches...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Hash < sorted[j].Hash })

	credentials := make([]credential, 0, len(sorted))
	for _, batch := range sorted {
		if batch == nil {
			continue
		}
		entry, err := buildCredential(batch, locale)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, entry)
	}

	return encMode.Marshal(database{
		Protocols:   append([]string(nil), protocols...),
		Credentials: credentials,
	})
}

func buildCredential(batch *models.MdocBatch, locale string) (credential, error) {
	// The entry id the matcher emits is space-delimited and the activity that
	// receives the user's choice splits on spaces expecting exactly three parts,
	// so a hash containing a space would route the selection to the wrong
	// credential or to none. Hashes are hex today and this cannot fire; it is
	// here because the failure it prevents is silent and happens on a phone.
	if strings.ContainsAny(batch.Hash, " ") {
		return credential{}, fmt.Errorf(
			"credential hash %q contains a space, which the credential manager entry id cannot carry", batch.Hash)
	}
	if batch.Hash == "" {
		return credential{}, fmt.Errorf("credential of docType %q has no hash to identify it by", batch.DocType)
	}

	display := services.ResolveMdocDisplay(batch, locale)

	// Same fallback the credential list applies: an issuer that published no
	// display text this locale can resolve still has to be nameable, and the
	// docType is the only name left.
	title := display.CredentialName
	if title == "" {
		title = batch.DocType
	}
	subtitle := display.IssuerName
	if subtitle == "" {
		subtitle = batch.CredentialIssuer
	}

	namespaces := make(map[string]map[string][3]string, len(batch.Namespaces))
	for namespace, elements := range batch.Namespaces {
		rendered := make(map[string][3]string, len(elements))
		for element := range elements {
			rendered[element] = renderElement(display, namespace, element)
		}
		namespaces[namespace] = rendered
	}

	return credential{
		Title:    title,
		Subtitle: subtitle,
		// Never nil: nil marshals to CBOR null and the matcher reads this key as
		// a byte string without checking.
		Bitmap: []byte{},
		Mdoc: &mdocEntry{
			DocumentId: batch.Hash,
			DocType:    batch.DocType,
			Namespaces: namespaces,
		},
	}, nil
}

// renderElement produces the [displayName, value, matchValue] triple for one
// data element.
func renderElement(display services.ResolvedBatchDisplay, namespace, element string) [3]string {
	name := display.ClaimNames[clientmodels.ClaimPathKey([]any{namespace, element})]
	if name == "" {
		// A backstop, not the usual path: ResolveMdocDisplay already names every
		// stored element, deriving "Age Over 18" for an age_over_NN and falling
		// back to the element identifier for anything else its metadata never
		// declared. This catches only a display resolution that stopped doing
		// that, where the cost would be a picker row with a blank label.
		name = element
	}

	// Both value slots are left empty, deliberately, and this is the one decision
	// in this file worth arguing for.
	//
	// The picker draws the second slot next to the element's name (the matcher's
	// AddFieldToEntrySet), and it draws it BEFORE the wallet has asked for a PIN
	// or a fingerprint. So filling it publishes every element of every credential
	// to anyone holding the unlocked phone, reachable by making any credential
	// request at all — and for an age credential that is the whole ladder,
	// age_over_21 false included.
	//
	// That is the same fact this wallet refuses to disclose over the wire. A
	// threshold answered false is a cryptographically certain statement that the
	// holder is under that age, which is why isomdoc drops it from a
	// presentation; putting it in system UI is a second channel for it, and
	// refusing on one while volunteering on the other is not a privacy position.
	//
	// Nothing needs them. The contract requires the slots to exist, not to be
	// populated: the matcher reads three strings and empty ones are strings. The
	// picker still lists which elements are being asked for, by name, which is
	// what a person choosing between credentials actually reads. And matching on
	// this transport never consults a value — an ISO itemsRequest carries element
	// identifiers and intentToRetain, and nothing else, so the DCQL the matcher
	// builds from it has no value constraint to compare against.
	//
	// The one thing this forecloses is value-constrained DCQL, which only the
	// OpenID4VP protocols can express. If those are ever registered for (see
	// client.CredentialManagerProtocols), the third slot becomes load-bearing and
	// this becomes a real trade rather than a free one — at which point it should
	// be decided per element, not reopened wholesale.
	return [3]string{name, "", ""}
}
