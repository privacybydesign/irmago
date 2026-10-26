package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// requireIdenticalCopies rejects a batch whose copies are not copies of one
// credential. The copies of a batch may differ only where they must: in their
// cryptographic material (holder binding key, digests and salts, signature)
// and in their status list entry, which each one-time-use copy needs for
// itself. Everything else, timestamps and identifiers included, must be equal.
//
// The wallet relies on this. A batch is shown, logged and deduplicated as one
// credential, from the values of one copy, while presentations send whichever
// copy is unused next. A copy that differs would leave the wallet showing the
// user one value and sending the verifier another. It would also make copies
// linkable, which is what using each copy once is meant to prevent.
//
// contentOf returns a copy's values with the parts that may differ removed.
// The type and issuer identity the parser derived are compared as well.
func requireIdenticalCopies(batch []*ParsedCredential, contentOf func(*ParsedCredential) map[string]any) error {
	if len(batch) < 2 {
		return nil
	}
	first := batch[0]
	firstContent := contentOf(first)
	for i, pc := range batch[1:] {
		if pc.VerifiableCredentialType != first.VerifiableCredentialType {
			return fmt.Errorf("credential %d has type %q but credential 0 has type %q; copies of one credential must be identical", i+1, pc.VerifiableCredentialType, first.VerifiableCredentialType)
		}
		if pc.IssuerIdentifier != first.IssuerIdentifier {
			return fmt.Errorf("credential %d is issued by %q but credential 0 by %q; copies of one credential must be identical", i+1, pc.IssuerIdentifier, first.IssuerIdentifier)
		}
		differing, err := differingKeys(firstContent, contentOf(pc))
		if err != nil {
			return fmt.Errorf("credential %d: %w", i+1, err)
		}
		if len(differing) > 0 {
			return fmt.Errorf("credential %d differs from credential 0 in %s; copies of one credential may differ only in their key binding and status list entry", i+1, strings.Join(differing, ", "))
		}
	}
	return nil
}

// differingKeys returns, sorted, the top-level keys whose values differ
// between a and b, counting a key present in only one of them.
func differingKeys(a, b map[string]any) ([]string, error) {
	var differing []string
	for key, aValue := range a {
		bValue, ok := b[key]
		if !ok {
			differing = append(differing, key)
			continue
		}
		// json.Marshal sorts object keys at every level, so equal values
		// encode to equal bytes.
		aBytes, err := json.Marshal(aValue)
		if err != nil {
			return nil, fmt.Errorf("failed to encode %q: %w", key, err)
		}
		bBytes, err := json.Marshal(bValue)
		if err != nil {
			return nil, fmt.Errorf("failed to encode %q: %w", key, err)
		}
		if !bytes.Equal(aBytes, bBytes) {
			differing = append(differing, key)
		}
	}
	for key := range b {
		if _, ok := a[key]; !ok {
			differing = append(differing, key)
		}
	}
	slices.Sort(differing)
	return differing, nil
}

// withoutKeys returns a shallow copy of payload without the given top-level keys.
func withoutKeys(payload sdjwt.ProcessedPayload, keys ...string) map[string]any {
	content := make(map[string]any, len(payload))
	for key, value := range payload {
		if !slices.Contains(keys, key) {
			content[key] = value
		}
	}
	return content
}

// sdJwtVcCopyContent is an SD-JWT VC copy's values without its key binding
// and its Token Status List reference. Digests and salts are already gone
// from the processed payload, but _sd and _sd_alg are dropped regardless.
func sdJwtVcCopyContent(pc *ParsedCredential) map[string]any {
	return withoutKeys(pc.SdJwtVc.ProcessedSdJwtPayload,
		sdjwt.ConfirmationKey, sdjwt.SdKey, sdjwt.SdAlgKey, sdjwtvc.StatusKey)
}

// sdJwtVcdmCopyContent is an SD-JWT-secured VCDM copy's values without its key
// binding and its status entries: the Token Status List reference and the
// W3C credentialStatus.
func sdJwtVcdmCopyContent(pc *ParsedCredential) map[string]any {
	return withoutKeys(pc.SdJwtVcdm.ProcessedSdJwtPayload,
		sdjwt.ConfirmationKey, sdjwt.SdKey, sdjwt.SdAlgKey, sdjwtvc.StatusKey, vcdm.CredentialStatusKey)
}

// mdocCopyContent is an mdoc copy's values: its doctype, its element values
// and its validity window. The device key, the digests and the status
// reference are left out.
func mdocCopyContent(pc *ParsedCredential) map[string]any {
	validity := pc.Mdoc.ValidityInfo
	return map[string]any{
		"docType":    pc.Mdoc.DocType,
		"namespaces": pc.Mdoc.Namespaces,
		"validityInfo": map[string]any{
			"signed":     validity.Signed.UTC(),
			"validFrom":  validity.ValidFrom.UTC(),
			"validUntil": validity.ValidUntil.UTC(),
		},
	}
}
