package services

import (
	"fmt"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// ============================================================
// CHOOSING AND SPENDING AN MDOC INSTANCE
// ============================================================
//
// An mdoc credential is stored as a BATCH of interchangeable single-use
// instances, so presenting one is two decisions rather than one: which instance
// answers this request, and when that instance counts as spent.
//
// Both were originally written inside mdoc_dcql.PrepareDisclosure, which was the
// only caller. Proximity (ISO 18013-5 device retrieval) is a second caller that
// needs identical semantics over a different transport, and a second copy of
// "which instance, and burn it afterwards" is exactly the kind of duplicate that
// drifts: an unlinkability property that holds on one transport and not the other
// is worse than one that holds on neither, because nothing looks broken.
//
// So the choice lives here once, and each transport supplies only what genuinely
// differs — which for ISO 18013-5 is the SessionTranscript the device signature
// is bound to, and nothing else.

// ReservedInstance is one credential instance, chosen for one presentation and
// not yet spent.
//
// Reserved rather than taken: holding this does not consume anything. The
// instance is spent by Spend, which is called only once the presentation it was
// reserved for has actually been built. See Spend for why that ordering matters.
type ReservedInstance struct {
	// Batch is the stored batch this instance came from.
	Batch *models.MdocBatch

	// Instance is the stored row, kept so Spend needs no second lookup.
	Instance *models.MdocBatchInstance

	// Document is the decoded credential: docType and IssuerSigned as issued,
	// with no DeviceSigned. The caller attaches a fresh one per presentation.
	Document stdmdoc.MDoc
}

// MdocInstanceSelector resolves a chosen credential to a concrete unused instance
// and records when one has been spent.
type MdocInstanceSelector struct {
	store db.MdocStore
}

// NewMdocInstanceSelector builds a selector over the wallet's mdoc tables.
func NewMdocInstanceSelector(store db.MdocStore) *MdocInstanceSelector {
	return &MdocInstanceSelector{store: store}
}

// Reserve finds an unused instance of the batch with the given content hash and
// decodes it, without consuming anything.
//
// The credential hash is what a DCQL disclosure selection identifies a credential
// by, and is the same identity on every transport: it is computed over docType,
// credential issuer and element values, so it names the credential rather than any
// particular copy of it.
func (s *MdocInstanceSelector) Reserve(credentialHash string) (*ReservedInstance, error) {
	batch, err := s.store.GetBatchByHash(credentialHash)
	if err != nil {
		return nil, fmt.Errorf("batch not found for hash %s: %w", credentialHash, err)
	}

	instance, err := s.store.GetUnusedInstance(batch.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get unused instance for batch %s: %w", batch.ID, err)
	}

	var document stdmdoc.MDoc
	if err := stdmdoc.Unmarshal(instance.IssuerSigned, &document); err != nil {
		return nil, fmt.Errorf("decode stored mdoc instance %s: %w", instance.ID, err)
	}

	return &ReservedInstance{Batch: batch, Instance: instance, Document: document}, nil
}

// Spend marks a reserved instance as presented.
//
// # Call this last
//
// Everything that can fail for a presentation must happen BEFORE this. A failure
// after the instance is marked used would consume a single-use document on a
// disclosure that then errored and never reached the verifier, and the credential
// would silently lose a use with nothing to show for it. The SD-JWT path orders
// itself the same way for the same reason.
//
// # A batch of one stays reusable
//
// An issuer that does not support batch issuance yields BatchSize == 1, and
// spending that single instance would leave the wallet holding a credential it can
// never present again. Such a batch is therefore left reusable — the unlinkability
// a batch buys is not available at BatchSize 1 anyway, so nothing is given up by
// keeping it usable. Mirrors the SD-JWT handler.
func (s *MdocInstanceSelector) Spend(reserved *ReservedInstance) error {
	if reserved == nil {
		return fmt.Errorf("no reserved instance to spend")
	}
	if reserved.Batch.BatchSize <= 1 {
		return nil
	}
	if err := s.store.MarkInstanceUsed(reserved.Instance.ID); err != nil {
		return fmt.Errorf("failed to mark instance as used: %w", err)
	}
	return nil
}

// SelectiveDiscloseNamespaces strips a document to the named elements, across any
// number of namespaces.
//
// stdmdoc.SelectiveDisclose handles one namespace per call, because that is the
// shape of ISO 18013-5's IssuerNameSpaces. A request is not so limited — 7.1 lets
// an issuing authority add namespaces, and a single DocRequest may name elements
// in several — so something has to run it per namespace and merge the results.
// This is that something, shared rather than duplicated: both the OpenID4VP path
// and the ISO 18013-5 proximity path disclose the same documents and must strip
// them identically, or the same credential would reveal different things depending
// on how it was asked.
//
// Namespaces absent from reveal are dropped entirely, which is the point: the
// merged document carries only what was selected.
func SelectiveDiscloseNamespaces(doc *stdmdoc.MDoc, reveal map[string][]string) (*stdmdoc.MDoc, error) {
	if doc == nil {
		return nil, fmt.Errorf("no document to disclose from")
	}

	merged := *doc
	merged.IssuerSigned.NameSpaces = make(map[string][]stdmdoc.Tag24Item, len(reveal))
	for namespace, elements := range reveal {
		disclosed, err := stdmdoc.SelectiveDisclose(doc, namespace, elements)
		if err != nil {
			return nil, err
		}
		merged.IssuerSigned.NameSpaces[namespace] = disclosed.IssuerSigned.NameSpaces[namespace]
	}
	return &merged, nil
}

// RevealFromClaimPaths turns DCQL claim paths into the per-namespace element lists
// SelectiveDiscloseNamespaces takes, dropping duplicates.
//
// mso_mdoc claim paths are always exactly [namespace, elementIdentifier]: ISO
// 18013-5 has no nested claims, unlike SD-JWT.
func RevealFromClaimPaths(claimPaths [][]any) (map[string][]string, error) {
	reveal := make(map[string][]string, len(claimPaths))
	seen := make(map[MdocElementRef]struct{}, len(claimPaths))

	for _, path := range claimPaths {
		ref, ok := MdocElementRefFromPath(path)
		if !ok {
			return nil, fmt.Errorf(
				"mso_mdoc claim path must start with [namespace, elementIdentifier], got %d component(s): %v",
				len(path), path)
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		reveal[ref.Namespace] = append(reveal[ref.Namespace], ref.Element)
	}
	return reveal, nil
}
