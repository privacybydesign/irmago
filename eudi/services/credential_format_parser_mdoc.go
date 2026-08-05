package services

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// mdocCredentialFormatParser is the mso_mdoc implementation of
// CredentialFormatParser.
type mdocCredentialFormatParser struct {
	verifier *mdoc.Verifier
}

// NewMdocCredentialFormatParser creates a CredentialFormatParser for
// mso_mdoc credentials, verifying issuerAuth against the given verifier's
// trust roots.
func NewMdocCredentialFormatParser(verifier *mdoc.Verifier) CredentialFormatParser {
	return &mdocCredentialFormatParser{verifier: verifier}
}

func (p *mdocCredentialFormatParser) ParseAndVerify(raw, credentialIssuer string, holderBindingKeyRequired bool) (*ParsedCredential, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode mdoc credential: %w", err)
	}
	var m mdoc.MDoc
	if err := cbor.Unmarshal(encoded, &m); err != nil {
		return nil, fmt.Errorf("failed to decode mdoc: %w", err)
	}

	resolved, result := p.verifier.VerifyAllDisclosedNamespaces(&m)
	if !result.Valid {
		return nil, fmt.Errorf("mdoc verification failed: %s", result.Error)
	}
	if holderBindingKeyRequired && result.DeviceKey == nil {
		return nil, fmt.Errorf("mdoc has no usable deviceKeyInfo but cryptographic key binding was required")
	}

	resolvedClaimsBytes, err := json.Marshal(resolved)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resolved mdoc claims: %w", err)
	}

	// Store the issuer-signed structure only — DeviceSigned is attached
	// fresh at every presentation (see mdoc_dcql.PrepareDisclosure).
	rawBytes, err := cbor.Marshal(mdoc.MDoc{DocType: m.DocType, IssuerSigned: m.IssuerSigned})
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode mdoc for storage: %w", err)
	}

	parsed := &ParsedCredential{
		Format: models.CredentialFormatMsoMdoc,
		// result.DocType, not m.DocType: the verifier reports the docType from the
		// signed MSO, while m.DocType is the document envelope's own copy, which no
		// signature covers. The two are now required to be equal for verification to
		// succeed at all, so this is belt-and-braces — but this value becomes the
		// credential's type, which DCQL doctype_value matching and relying-party
		// authorization key off, so it should visibly come from the signed side.
		VerifiableCredentialType: result.DocType,
		IssuerURL:                credentialIssuer,
		ResolvedClaims:           resolvedClaimsBytes,
		RawCredentialBytes:       rawBytes,
		IssuedAt:                 unixPtrIfNotZero(result.ValidityInfo.Signed),
		ExpiresAt:                unixPtrIfNotZero(result.ValidityInfo.ValidUntil),
		NotBefore:                unixPtrIfNotZero(result.ValidityInfo.ValidFrom),
	}

	if result.DeviceKey != nil {
		thumbprint, err := jwkThumbprintFromECDSAPublicKey(result.DeviceKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute device key thumbprint: %w", err)
		}
		parsed.HolderBindingKeyThumbprint = &thumbprint
		// The key itself as well as its thumbprint: a DID-bound stored key has no
		// thumbprint to match against, and the DID forms are derived from the key.
		// See ParsedCredential.HolderBindingKeyPublicKey.
		parsed.HolderBindingKeyPublicKey = result.DeviceKey
	}

	return parsed, nil
}

func (p *mdocCredentialFormatParser) CheckBatchUniqueness(batch []*ParsedCredential) error {
	seen := make(map[string]bool, len(batch))
	for i, pc := range batch {
		if pc.HolderBindingKeyThumbprint == nil {
			continue
		}
		if seen[*pc.HolderBindingKeyThumbprint] {
			return fmt.Errorf("credential %d reuses a device key already used earlier in this batch", i)
		}
		seen[*pc.HolderBindingKeyThumbprint] = true
	}
	return nil
}

func jwkThumbprintFromECDSAPublicKey(pub any) (string, error) {
	key, err := jwk.Import(pub)
	if err != nil {
		return "", fmt.Errorf("convert ecdsa pub key to jwk: %w", err)
	}
	thumbprintBytes, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute thumbprint: %w", err)
	}
	return hex.EncodeToString(thumbprintBytes), nil
}

// unixPtrIfNotZero returns a pointer to t.Unix(), or nil if t is the zero
// time.Time (i.e. the underlying claim was absent).
func unixPtrIfNotZero(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	x := t.Unix()
	return &x
}
