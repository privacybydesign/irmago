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
	m, err := decodeIssuedMdoc(encoded)
	if err != nil {
		return nil, err
	}

	resolved, result := p.verifier.VerifyAllDisclosedNamespaces(m)
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

// decodeIssuedMdoc reads the credential an issuer returns at the OpenID4VCI
// credential endpoint, which is not one fixed shape in practice.
//
// OpenID4VCI's mso_mdoc profile says the credential is the base64url-encoded
// CBOR of an IssuerSigned structure, and a Document (docType + issuerSigned) is
// the natural thing to send when the docType has to travel with it. The EUDI
// reference issuer sends neither: it returns a whole DeviceResponse envelope,
// documents array and all (see cbor2elems in its formatter_func.py, which reads
// its own output back as documents[0].issuerSigned). Decoding that into a
// Document silently produced a zero-valued struct, so the credential failed with
// "empty COSE_Sign1" — a decode mismatch reported as if the issuer's signature
// were malformed.
//
// Reading is therefore permissive across all three, matching decodeCoseSign1's
// reasoning in the mdoc package: nothing here is trusted on the strength of its
// container, since the MSO's signature and its docType are checked afterwards
// either way.
func decodeIssuedMdoc(encoded []byte) (*mdoc.MDoc, error) {
	// Document first: it carries the envelope docType, which the verifier binds
	// to the signed one.
	var doc mdoc.MDoc
	if err := cbor.Unmarshal(encoded, &doc); err == nil && len(doc.IssuerSigned.IssuerAuth) > 0 {
		return &doc, nil
	}

	var resp mdoc.DeviceResponse
	if err := cbor.Unmarshal(encoded, &resp); err == nil && len(resp.Documents) > 0 {
		if len(resp.Documents) > 1 {
			return nil, fmt.Errorf("mdoc credential holds %d documents; expected exactly one", len(resp.Documents))
		}
		if len(resp.Documents[0].IssuerSigned.IssuerAuth) == 0 {
			return nil, fmt.Errorf("mdoc credential's document carries no issuerAuth")
		}
		return &resp.Documents[0], nil
	}

	// Bare IssuerSigned: no envelope docType exists to bind, so it is taken from
	// the MSO the issuer signed. Leaving it empty would fail the verifier's
	// docType check against a value the issuer never sent.
	var issuerSigned mdoc.IssuerSigned
	if err := cbor.Unmarshal(encoded, &issuerSigned); err == nil && len(issuerSigned.IssuerAuth) > 0 {
		docType, err := mdoc.DocTypeFromIssuerAuth(issuerSigned.IssuerAuth)
		if err != nil {
			return nil, fmt.Errorf("failed to read docType from issuerAuth: %w", err)
		}
		return &mdoc.MDoc{DocType: docType, IssuerSigned: issuerSigned}, nil
	}

	return nil, fmt.Errorf("mdoc credential is neither a Document, a DeviceResponse nor an IssuerSigned structure")
}
