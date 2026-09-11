package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"sort"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/proximity"
)

// wallet is an in-memory stand-in for the real one: it holds credentials this tool
// minted itself and approves whatever it is asked for.
//
// It is NOT the wallet from client/ — that one needs SQLCipher storage, the DCQL
// handler and a user to press a button. This is a bring-up tool, and the thing
// under test is the transport beneath it, not candidate selection.
//
// Auto-approval is deliberate and is stated on screen, so nobody mistakes this for
// the consent behaviour of the product.
type wallet struct {
	credentials map[string]stdmdoc.MDoc   // docType -> credential
	namespaces  map[string]string         // docType -> namespace its elements live in
	holders     map[string]stdmdoc.Holder // docType -> the key its MSO is bound to
	issuer      *stdmdoc.Issuer
}

var (
	_ proximity.Discloser       = (*wallet)(nil)
	_ proximity.DeviceKeyBinder = (*wallet)(nil)
)

// newWallet mints one age verification credential and one mDL.
//
// Both, because the two exercise opposite halves of the 7.2.1 release policy
// against a reader this wallet does not trust — which is every reader here, since
// the Multipaz test app's reader certificate chains to nothing we hold:
//
//   - eu.europa.ec.av.1 is not an mDL, so an unauthenticated reader gets NOTHING
//     and a documentError. That is the mandatory-reader-auth policy.
//   - org.iso.18013.5.1.mDL releases its Table 5 mandatory elements anyway,
//     because "An mDL shall not require mdoc reader authentication as a
//     precondition for the release of any of the mandatory data elements".
//
// So the driving licence entry in the reader's dropdown is the one that returns
// data without any trust setup, and the age one demonstrates the refusal. Both
// outcomes are correct; seeing them side by side is the point.
func newWallet() (*wallet, error) {
	issuer, err := stdmdoc.NewIssuer()
	if err != nil {
		return nil, fmt.Errorf("create the test issuer: %w", err)
	}

	w := &wallet{
		credentials: map[string]stdmdoc.MDoc{},
		namespaces:  map[string]string{},
		holders:     map[string]stdmdoc.Holder{},
		issuer:      issuer,
	}

	if err := w.mint(stdmdoc.AgeVerificationDocType, stdmdoc.AgeVerificationDocType, map[string]any{
		"age_over_18": true,
		"age_over_21": true,
		"age_over_65": false,
	}); err != nil {
		return nil, err
	}

	// The eleven mandatory elements of Table 5, so the 7.2.1 carve-out has
	// something real to release, plus two optional ones to show being withheld.
	if err := w.mint(stdmdoc.MDLDocType, stdmdoc.MDLNameSpace, map[string]any{
		"family_name": "de Vries",
		"given_name":  "Erika",
		// Table 5 types these three as full-date, and 18013-5 defines
		// full-date = #6.1004(tstr) — CBOR tag 1004, per RFC 8943. A bare text
		// string decodes but is the wrong type, and a conformant reader says so:
		// Multipaz rendered these as "error occurred during rendering:
		// org.multipaz.cbor.Tstr cannot be cast to org.multipaz.cbor.Tagged".
		//
		// irmago's own READING path already handles this correctly — see
		// cborTagFullDate in eudi/services/mdoc_claim_values.go — so only this
		// fixture was wrong. mdoc.Issuer.Issue is deliberately docType-agnostic
		// and signs whatever it is handed, which is why the type has to be right
		// here rather than inferred there.
		"birth_date":             fullDate("1971-09-01"),
		"issue_date":             fullDate("2024-01-15"),
		"expiry_date":            fullDate("2034-01-14"),
		"issuing_country":        "NL",
		"issuing_authority":      "RDW",
		"document_number":        "NL1234567",
		"portrait":               []byte{0xff, 0xd8, 0xff, 0xe0},
		"driving_privileges":     []any{},
		"un_distinguishing_sign": "NL",
		// Not mandatory in Table 5 — withheld from an unauthenticated reader.
		"age_over_18": true,
		"nationality": "NL",
	}); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *wallet) mint(docType, namespace string, claims map[string]any) error {
	holder, err := stdmdoc.NewHolder()
	if err != nil {
		return fmt.Errorf("create a device key for %s: %w", docType, err)
	}
	credential, err := w.issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		return fmt.Errorf("issue %s: %w", docType, err)
	}
	w.credentials[docType] = *credential
	w.namespaces[docType] = namespace
	w.holders[docType] = holder
	return nil
}

// IACACert is the anchor a reader would need to verify what this wallet presents.
// Printed on startup so it can be handed to a reader that wants to check it.
func (w *wallet) IACACert() *x509.Certificate { return w.issuer.IACACert() }

// Disclose approves everything the request is permitted to ask for.
//
// "Permitted" is the operative word: Session has already applied reader
// authentication and the 7.2.1 policy, so what arrives here is narrowed. This
// never sees an element the reader is not entitled to, which is why approving
// everything is safe in a tool like this.
func (w *wallet) Disclose(request proximity.DisclosureRequest) ([]proximity.Selection, error) {
	var selections []proximity.Selection

	for _, document := range request.Documents {
		fmt.Printf("\n  request for %s\n", document.DocType)
		switch {
		case document.Authenticated():
			fmt.Printf("    reader authenticated: %s\n", document.Reader.CommonName())
		case document.ReaderAuthErr != nil:
			fmt.Printf("    reader authentication FAILED: %v\n", document.ReaderAuthErr)
		default:
			fmt.Printf("    reader sent no readerAuth\n")
		}
		fmt.Printf("    asked for : %s\n", elementList(document.Requested))
		fmt.Printf("    permitted : %s\n", elementList(document.Permitted))

		credential, held := w.credentials[document.DocType]
		if !held {
			fmt.Printf("    -> this wallet holds no %s\n", document.DocType)
			continue
		}

		namespace := w.namespaces[document.DocType]
		available := map[string]bool{}
		disclosed, err := credential.DisclosedElements()
		if err != nil {
			return nil, err
		}
		for _, id := range disclosed[namespace] {
			available[id] = true
		}

		var reveal []string
		for _, elements := range document.Permitted.NameSpaces {
			for id := range elements {
				if available[id] {
					reveal = append(reveal, id)
				}
			}
		}
		sort.Strings(reveal)

		if len(reveal) == 0 {
			fmt.Printf("    -> nothing releasable, the reader gets a documentError\n")
			continue
		}
		fmt.Printf("    -> releasing: %v\n", reveal)

		selections = append(selections, proximity.Selection{
			Document: credential,
			Reveal:   map[string][]string{namespace: reveal},
		})
	}

	return selections, nil
}

// HolderForDeviceKey finds the key a credential's MSO is bound to.
func (w *wallet) HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (stdmdoc.Holder, error) {
	for _, holder := range w.holders {
		if holder.PublicKey().Equal(deviceKey) {
			return holder, nil
		}
	}
	return nil, fmt.Errorf("no device key in this wallet matches the credential's MSO")
}

// elementList renders an ItemsRequest's elements for the console.
func elementList(items stdmdoc.ItemsRequest) string {
	var all []string
	for namespace, elements := range items.NameSpaces {
		for id := range elements {
			all = append(all, namespace+"/"+id)
		}
	}
	if len(all) == 0 {
		return "(nothing)"
	}
	sort.Strings(all)
	return fmt.Sprintf("%v", all)
}

// fullDate wraps a YYYY-MM-DD string as ISO/IEC 18013-5's full-date type:
// full-date = #6.1004(tstr), where tag 1004 is RFC 8943's.
//
// Table 5 types birth_date, issue_date and expiry_date this way. Sending a bare
// text string instead produces a document that verifies — the digest and the
// signature are over whatever bytes were signed — and then fails to render at a
// conformant reader, which is a good illustration of why "it verified" is not the
// same as "it is correct".
func fullDate(text string) cbor.Tag {
	return cbor.Tag{Number: 1004, Content: text}
}
