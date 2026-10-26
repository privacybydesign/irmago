package services

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
)

const copyTestIssuer = "https://issuer.example.com"

func sdJwtVcCopy(payload sdjwt.ProcessedPayload) *ParsedCredential {
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: "https://example.com/vct/email",
		IssuerIdentifier:         copyTestIssuer,
		SdJwtVc:                  &sdjwtvc.VerifiedSdJwtVc{ProcessedSdJwtPayload: payload},
	}
}

func sdJwtVcCopyPayload(overrides map[string]any) sdjwt.ProcessedPayload {
	payload := sdjwt.ProcessedPayload{
		"iss":   copyTestIssuer,
		"vct":   "https://example.com/vct/email",
		"iat":   float64(1700000000),
		"jti":   "urn:uuid:1",
		"email": "alice@example.com",
	}
	for key, value := range overrides {
		if value == nil {
			delete(payload, key)
		} else {
			payload[key] = value
		}
	}
	return payload
}

func TestSdJwtVcCheckBatch_CopiesMayDifferInKeyBindingAndStatusOnly(t *testing.T) {
	parser := NewSdJwtVcCredentialFormatParser(nil)
	err := parser.CheckBatch([]*ParsedCredential{
		sdJwtVcCopy(sdJwtVcCopyPayload(map[string]any{
			"cnf":     map[string]any{"jwk": map[string]any{"x": "a"}},
			"status":  map[string]any{"status_list": map[string]any{"idx": float64(1), "uri": "https://example.com/sl"}},
			"_sd_alg": "sha-256",
		})),
		sdJwtVcCopy(sdJwtVcCopyPayload(map[string]any{
			"cnf":    map[string]any{"jwk": map[string]any{"x": "b"}},
			"status": map[string]any{"status_list": map[string]any{"idx": float64(2), "uri": "https://example.com/sl"}},
		})),
	})
	require.NoError(t, err)
}

func TestSdJwtVcCheckBatch_RejectsDifferingCopies(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		differing string
	}{
		{"claim value", map[string]any{"email": "bob@example.com"}, "email"},
		{"issuance time", map[string]any{"iat": float64(1700000001)}, "iat"},
		{"token identifier", map[string]any{"jti": "urn:uuid:2"}, "jti"},
		{"claim only in one copy", map[string]any{"phone": "0612345678"}, "phone"},
		{"claim missing from one copy", map[string]any{"email": nil}, "email"},
	}
	parser := NewSdJwtVcCredentialFormatParser(nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := parser.CheckBatch([]*ParsedCredential{
				sdJwtVcCopy(sdJwtVcCopyPayload(nil)),
				sdJwtVcCopy(sdJwtVcCopyPayload(tc.overrides)),
			})
			require.ErrorContains(t, err, "credential 1 differs from credential 0 in "+tc.differing)
		})
	}
}

func TestSdJwtVcCheckBatch_RejectsCopiesFromDifferentIssuers(t *testing.T) {
	other := sdJwtVcCopy(sdJwtVcCopyPayload(nil))
	other.IssuerIdentifier = "https://other.example.com"

	err := NewSdJwtVcCredentialFormatParser(nil).CheckBatch([]*ParsedCredential{
		sdJwtVcCopy(sdJwtVcCopyPayload(nil)),
		other,
	})
	require.ErrorContains(t, err, "issued by")
}

func vcdmCopy(subjectId, validFrom string, credentialStatus any) *ParsedCredential {
	payload := sdjwt.ProcessedPayload{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "EmailCredential"},
		"issuer":            copyTestIssuer,
		"validFrom":         validFrom,
		"credentialSubject": map[string]any{"id": subjectId, "email": "alice@example.com"},
	}
	if credentialStatus != nil {
		payload["credentialStatus"] = credentialStatus
	}
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVcdm,
		VerifiableCredentialType: "EmailCredential",
		IssuerIdentifier:         copyTestIssuer,
		SdJwtVcdm:                &vcdmsdjwt.VerifiedSdJwtVcdm{ProcessedSdJwtPayload: payload},
	}
}

func TestSdJwtVcdmCheckBatch(t *testing.T) {
	parser := NewSdJwtVcdmCredentialFormatParser(nil)
	const validFrom = "2026-10-26T12:00:00Z"

	t.Run("copies may differ in their status entry", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmCopy("did:key:a", validFrom, map[string]any{"statusListIndex": "1"}),
			vcdmCopy("did:key:a", validFrom, map[string]any{"statusListIndex": "2"}),
		})
		require.NoError(t, err)
	})

	t.Run("copies may not differ in credentialSubject.id", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmCopy("did:key:a", validFrom, nil),
			vcdmCopy("did:key:b", validFrom, nil),
		})
		require.ErrorContains(t, err, "differs from credential 0 in credentialSubject")
	})

	t.Run("copies may not differ in validFrom", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmCopy("did:key:a", validFrom, nil),
			vcdmCopy("did:key:a", "2026-10-26T12:00:01Z", nil),
		})
		require.ErrorContains(t, err, "differs from credential 0 in validFrom")
	})
}

func mdocCopy(thumbprint string, ageOver18 bool, signed time.Time) *ParsedCredential {
	return &ParsedCredential{
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: "eu.europa.ec.av.1",
		IssuerIdentifier:         copyTestIssuer,
		Mdoc: &ParsedMdoc{
			DocType:             "eu.europa.ec.av.1",
			Namespaces:          models.MdocNamespaces{"eu.europa.ec.av.1": {"age_over_18": ageOver18}},
			ValidityInfo:        mdoc.ValidityInfo{Signed: signed, ValidFrom: signed, ValidUntil: signed.Add(24 * time.Hour)},
			DeviceKeyThumbprint: thumbprint,
		},
	}
}

func TestMdocCheckBatch_RejectsDifferingCopies(t *testing.T) {
	parser := NewMdocCredentialFormatParser(nil)
	signed := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	t.Run("copies may differ in their device key", func(t *testing.T) {
		// The same instant in another zone is the same validity window.
		err := parser.CheckBatch([]*ParsedCredential{
			mdocCopy("key-a", true, signed),
			mdocCopy("key-b", true, signed.In(time.FixedZone("CET", 3600))),
		})
		require.NoError(t, err)
	})

	t.Run("copies may not differ in an element value", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			mdocCopy("key-a", true, signed),
			mdocCopy("key-b", false, signed),
		})
		require.ErrorContains(t, err, "differs from credential 0 in namespaces")
	})

	t.Run("copies may not differ in their validity window", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			mdocCopy("key-a", true, signed),
			mdocCopy("key-b", true, signed.Add(time.Second)),
		})
		require.ErrorContains(t, err, "differs from credential 0 in validityInfo")
	})
}
