package vcdm

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	// ContextV2 is the VCDM 2.0 base context. VCDM 2.0 §4.3 requires it to be
	// the first entry of `@context`. It is a permanently-cacheable, hash-pinned
	// file (Appendix B.1) that a wallet should bundle offline rather than fetch.
	ContextV2 = "https://www.w3.org/ns/credentials/v2"

	// TypeVerifiableCredential is the base type every verifiable credential's
	// `type` must include (VCDM 2.0 §4.5).
	TypeVerifiableCredential = "VerifiableCredential"

	// MediaTypeCredential / MediaTypePresentation are the VCDM 2.0 media types
	// for a bare credential / presentation document (§6.1). Securing layers
	// wrap these in their own media type (e.g. `vc+sd-jwt`).
	MediaTypeCredential   = "application/vc"
	MediaTypePresentation = "application/vp"
)

// Top-level VCDM property names.
const (
	ContextKey           = "@context"
	TypeKey              = "type"
	IssuerKey            = "issuer"
	IDKey                = "id"
	CredentialSubjectKey = "credentialSubject"
	ValidFromKey         = "validFrom"
	ValidUntilKey        = "validUntil"
	CredentialStatusKey  = "credentialStatus"
	CredentialSchemaKey  = "credentialSchema"
	TermsOfUseKey        = "termsOfUse"
	EvidenceKey          = "evidence"
	RefreshServiceKey    = "refreshService"
)

// ErrMalformed is returned (wrapped) by Validate when the decoded document is
// not a conforming VCDM 2.0 document. It corresponds to the VCDM 2.0 §7.1
// MALFORMED_VALUE_ERROR. Callers can test for it with errors.Is.
var ErrMalformed = errors.New("malformed VCDM document")

// typedExtensionPoints are the optional properties that, when present, must be
// an object or array of objects where every object carries its own `type`
// (VCDM 2.0 §§4.10–4.11, 5.4–5.6).
var typedExtensionPoints = []string{
	CredentialStatusKey,
	CredentialSchemaKey,
	TermsOfUseKey,
	EvidenceKey,
	RefreshServiceKey,
}

// Document is a decoded W3C VCDM 2.0 verifiable credential: the logical JSON
// document, after any securing mechanism (SD-JWT / JOSE / Data Integrity) has
// been decoded and — for selective-disclosure mechanisms — after the disclosed
// values have been merged in. It is the "conforming document" of VCDM 2.0 §1.3.
//
// It is a map rather than a struct so the open-world JSON-LD document survives
// round-trips losslessly; typed accessors below enforce shape on read.
type Document map[string]any

// Contexts returns the raw `@context` entries (each is a string URL or, for an
// inline context, an object), or nil when `@context` is absent or not an array.
func (d Document) Contexts() []any {
	list, ok := d[ContextKey].([]any)
	if !ok {
		return nil
	}
	return list
}

// PrimaryContext returns the first `@context` entry as a string. The boolean is
// false when `@context` is absent, empty, or its first entry is not a string.
func (d Document) PrimaryContext() (string, bool) {
	list := d.Contexts()
	if len(list) == 0 {
		return "", false
	}
	s, ok := list[0].(string)
	return s, ok
}

// Types returns the credential's `type` values as a slice of strings. A single
// string `type` is normalised to a one-element slice; non-string members of a
// `type` array are skipped.
func (d Document) Types() []string {
	return toStringSlice(d[TypeKey])
}

// HasType reports whether the credential's `type` includes t.
func (d Document) HasType(t string) bool {
	return slices.Contains(d.Types(), t)
}

// ID returns the top-level `id` of the credential, if present as a string.
func (d Document) ID() (string, bool) {
	s, ok := d[IDKey].(string)
	return s, ok
}

// IssuerID returns the issuer identifier: the `issuer` value when it is a
// string, or its `id` member when `issuer` is an object (VCDM 2.0 §4.7).
// Returns ErrMalformed when `issuer` is absent, empty, or the wrong shape.
func (d Document) IssuerID() (string, error) {
	raw, ok := d[IssuerKey]
	if !ok {
		return "", fmt.Errorf("%w: missing required property %q", ErrMalformed, IssuerKey)
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return "", fmt.Errorf("%w: %q is an empty string", ErrMalformed, IssuerKey)
		}
		return v, nil
	case map[string]any:
		id, ok := v[IDKey].(string)
		if !ok || id == "" {
			return "", fmt.Errorf("%w: %q object is missing a string %q", ErrMalformed, IssuerKey, IDKey)
		}
		return id, nil
	default:
		return "", fmt.Errorf("%w: %q must be a URL string or an object with an %q, got %T", ErrMalformed, IssuerKey, IDKey, raw)
	}
}

// CredentialSubjects returns the credential subject(s) as objects. A single
// object is normalised to a one-element slice (VCDM 2.0 §4.8). Returns
// ErrMalformed when `credentialSubject` is absent, a non-object (e.g. a bare
// string), or an empty/heterogeneous array.
func (d Document) CredentialSubjects() ([]map[string]any, error) {
	raw, ok := d[CredentialSubjectKey]
	if !ok {
		return nil, fmt.Errorf("%w: missing required property %q", ErrMalformed, CredentialSubjectKey)
	}
	objs, ok := asObjectSlice(raw)
	if !ok {
		return nil, fmt.Errorf("%w: %q must be an object or array of objects, got %T", ErrMalformed, CredentialSubjectKey, raw)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("%w: %q array is empty", ErrMalformed, CredentialSubjectKey)
	}
	return objs, nil
}

// ValidFrom returns the `validFrom` timestamp. The boolean is false when the
// (optional) property is absent; an error is returned when it is present but
// not a well-formed dateTimeStamp (VCDM 2.0 §4.9).
func (d Document) ValidFrom() (time.Time, bool, error) {
	return d.timestamp(ValidFromKey)
}

// ValidUntil returns the `validUntil` timestamp; see ValidFrom.
func (d Document) ValidUntil() (time.Time, bool, error) {
	return d.timestamp(ValidUntilKey)
}

func (d Document) timestamp(key string) (time.Time, bool, error) {
	raw, ok := d[key]
	if !ok {
		return time.Time{}, false, nil
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, false, fmt.Errorf("%w: %q must be a dateTimeStamp string, got %T", ErrMalformed, key, raw)
	}
	t, err := parseDateTimeStamp(s)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%w: %q is not a valid dateTimeStamp: %v", ErrMalformed, key, err)
	}
	return t, true, nil
}

// Validate checks that d is a conforming VCDM 2.0 document (§1.3 + Appendix A):
// the structural invariants that must hold regardless of securing mechanism.
// Per VCDM 2.0 §7.1 a securing layer MUST call this only *after* verifying the
// mechanism-specific proof, on the decoded/disclosed document. It does not
// check point-in-time validity — see VerifyValidityPeriod — nor does it perform
// JSON-LD expansion (VCDM 2.0 §6.3 lightweight path).
//
// All violations are reported wrapping ErrMalformed.
func (d Document) Validate() error {
	// §4.3: `@context` present, non-empty, first entry exactly the base URL.
	ctx, ok := d.PrimaryContext()
	if !ok {
		return fmt.Errorf("%w: %q must be a non-empty array whose first entry is a string", ErrMalformed, ContextKey)
	}
	if ctx != ContextV2 {
		return fmt.Errorf("%w: %q[0] must be %q, got %q", ErrMalformed, ContextKey, ContextV2, ctx)
	}

	// §4.5: `type` present and includes VerifiableCredential.
	if _, ok := d[TypeKey]; !ok {
		return fmt.Errorf("%w: missing required property %q", ErrMalformed, TypeKey)
	}
	if !d.HasType(TypeVerifiableCredential) {
		return fmt.Errorf("%w: %q must include %q", ErrMalformed, TypeKey, TypeVerifiableCredential)
	}

	// §4.7: `issuer` present as a URL string or object with an `id`.
	if _, err := d.IssuerID(); err != nil {
		return err
	}

	// §4.8: `credentialSubject` present as an object or array of objects.
	if _, err := d.CredentialSubjects(); err != nil {
		return err
	}

	// §4.9: `validFrom`/`validUntil`, if present, well-formed and ordered.
	validFrom, hasFrom, err := d.ValidFrom()
	if err != nil {
		return err
	}
	validUntil, hasUntil, err := d.ValidUntil()
	if err != nil {
		return err
	}
	if hasFrom && hasUntil && validUntil.Before(validFrom) {
		return fmt.Errorf("%w: %q (%s) is before %q (%s)", ErrMalformed, ValidUntilKey, validUntil, ValidFromKey, validFrom)
	}

	// §§4.10–4.11, 5.4–5.6: typed extension points each carry their own `type`.
	for _, key := range typedExtensionPoints {
		if err := d.validateTypedExtension(key); err != nil {
			return err
		}
	}

	return nil
}

func (d Document) validateTypedExtension(key string) error {
	raw, ok := d[key]
	if !ok {
		return nil
	}
	objs, ok := asObjectSlice(raw)
	if !ok {
		return fmt.Errorf("%w: %q must be an object or array of objects, got %T", ErrMalformed, key, raw)
	}
	if len(objs) == 0 {
		return fmt.Errorf("%w: %q array is empty", ErrMalformed, key)
	}
	for i, obj := range objs {
		if !hasType(obj) {
			return fmt.Errorf("%w: %q entry %d is missing a %q", ErrMalformed, key, i, TypeKey)
		}
	}
	return nil
}

// VerifyValidityPeriod checks that now (± skew) falls within the credential's
// `validFrom`/`validUntil` window. Absent bounds are treated as open. A
// malformed timestamp is reported wrapping ErrMalformed; being outside the
// window is reported as an ordinary error. This is intentionally separate from
// Validate so structural conformance and point-in-time validity can be checked
// (and tested) independently.
func (d Document) VerifyValidityPeriod(now time.Time, skew time.Duration) error {
	validFrom, hasFrom, err := d.ValidFrom()
	if err != nil {
		return err
	}
	validUntil, hasUntil, err := d.ValidUntil()
	if err != nil {
		return err
	}
	if hasFrom && now.Add(skew).Before(validFrom) {
		return fmt.Errorf("credential is not yet valid: %q is %s, now is %s", ValidFromKey, validFrom, now)
	}
	if hasUntil && now.Add(-skew).After(validUntil) {
		return fmt.Errorf("credential has expired: %q is %s, now is %s", ValidUntilKey, validUntil, now)
	}
	return nil
}

// parseDateTimeStamp parses an XSD dateTimeStamp (VCDM 2.0 §4.9). A
// dateTimeStamp always carries a timezone offset, which RFC 3339 also requires,
// so RFC 3339 parsing (fractional seconds included) is an accurate check.
func parseDateTimeStamp(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// asObjectSlice normalises a "single object or array of objects" value into a
// slice of objects. The boolean is false when v is neither an object nor an
// array-of-objects (e.g. a bare string, or an array with a non-object member).
func asObjectSlice(v any) ([]map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return []map[string]any{x}, true
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			obj, ok := e.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, obj)
		}
		return out, true
	default:
		return nil, false
	}
}

// toStringSlice normalises a "single string or array of strings" value into a
// slice of strings; a single string becomes a one-element slice and non-string
// array members are skipped. Returns nil for any other type.
func toStringSlice(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// hasType reports whether obj carries a non-empty `type` (a non-empty string or
// a non-empty array).
func hasType(obj map[string]any) bool {
	raw, ok := obj[TypeKey]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	default:
		return false
	}
}
