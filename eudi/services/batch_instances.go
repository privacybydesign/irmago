package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// requireIdenticalBatchInstances rejects a batch whose instances are not
// instances of one credential. The instances of a batch may differ in their
// cryptographic material (holder binding key, digests and salts, signature), in
// their status list entry, and in their per-issuance identifier and issuance
// time. Each one-time-use instance needs its own status entry, and an issuer
// that gives each instance its own identifier or issuance time keeps the
// instances unlinkable. Everything else, the validity window included, must be
// equal.
//
// The wallet relies on this. A batch is shown, logged and deduplicated as one
// credential, from the values of one instance, while presentations send
// whichever instance is unused next. An instance that differs in a claim or its
// validity would leave the wallet showing the user one value and sending the
// verifier another.
//
// contentOf returns an instance's values with the parts that may differ removed.
// The type and issuer identity the parser derived are compared as well.
func requireIdenticalBatchInstances(batch []*ParsedCredential, contentOf func(*ParsedCredential) map[string]any) error {
	if len(batch) < 2 {
		return nil
	}
	first := batch[0]
	firstContent := contentOf(first)
	for i, pc := range batch[1:] {
		if pc.VerifiableCredentialType != first.VerifiableCredentialType {
			return fmt.Errorf("credential %d has type %q but credential 0 has type %q; batch instances of one credential must be identical", i+1, pc.VerifiableCredentialType, first.VerifiableCredentialType)
		}
		if pc.IssuerIdentifier != first.IssuerIdentifier {
			return fmt.Errorf("credential %d is issued by %q but credential 0 by %q; batch instances of one credential must be identical", i+1, pc.IssuerIdentifier, first.IssuerIdentifier)
		}
		differing, err := differingKeys(firstContent, contentOf(pc))
		if err != nil {
			return fmt.Errorf("credential %d: %w", i+1, err)
		}
		if len(differing) > 0 {
			return fmt.Errorf("credential %d differs from credential 0 in %s; batch instances of one credential may differ only in their key binding, status list entry, identifier and issuance time", i+1, strings.Join(differing, ", "))
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

// sdJwtVcBatchInstanceContent is an SD-JWT VC batch instance's values without its key binding,
// its Token Status List reference, its jti and its iat. Digests and salts are
// already gone from the processed payload, but _sd and _sd_alg are dropped
// regardless.
func sdJwtVcBatchInstanceContent(pc *ParsedCredential) map[string]any {
	return withoutKeys(pc.SdJwtVc.ProcessedSdJwtPayload,
		sdjwt.ConfirmationKey, sdjwt.SdKey, sdjwt.SdAlgKey, statuslist.StatusClaimKey,
		jwt.JwtIDKey, jwt.IssuedAtKey)
}

// sdJwtVcdmBatchInstanceContent is an SD-JWT-secured VCDM batch instance's values without its key
// binding, its status entries (the Token Status List reference and the W3C
// credentialStatus), its identifiers (jti and the credential id) and its iat.
// credentialSubject.id is content and must match.
func sdJwtVcdmBatchInstanceContent(pc *ParsedCredential) map[string]any {
	return withoutKeys(sdjwt.ProcessedPayload(pc.SdJwtVcdm.Document),
		sdjwt.ConfirmationKey, sdjwt.SdKey, sdjwt.SdAlgKey, statuslist.StatusClaimKey, vcdm.CredentialStatusKey,
		jwt.JwtIDKey, vcdm.IDKey, jwt.IssuedAtKey)
}

// mdocBatchInstanceContent is an mdoc batch instance's values: its doctype, its element values
// and its validity window. The device key, the digests, the status reference
// and the signing time are left out.
func mdocBatchInstanceContent(pc *ParsedCredential) map[string]any {
	validity := pc.Mdoc.ValidityInfo
	return map[string]any{
		"docType":    pc.Mdoc.DocType,
		"namespaces": pc.Mdoc.Namespaces,
		"validityInfo": map[string]any{
			"validFrom":  validity.ValidFrom.UTC(),
			"validUntil": validity.ValidUntil.UTC(),
		},
	}
}
