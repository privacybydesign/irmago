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

const batchInstanceTestIssuer = "https://issuer.example.com"

func sdJwtVcBatchInstance(payload sdjwt.ProcessedPayload) *ParsedCredential {
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: "https://example.com/vct/email",
		IssuerIdentifier:         batchInstanceTestIssuer,
		SdJwtVc:                  &sdjwtvc.VerifiedSdJwtVc{ProcessedSdJwtPayload: payload},
	}
}

func sdJwtVcBatchInstancePayload(overrides map[string]any) sdjwt.ProcessedPayload {
	payload := sdjwt.ProcessedPayload{
		"iss":   batchInstanceTestIssuer,
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

func TestSdJwtVcCheckBatch_InstancesMayDifferInKeyBindingStatusAndIdentifiers(t *testing.T) {
	parser := NewSdJwtVcCredentialFormatParser(nil)
	err := parser.CheckBatch([]*ParsedCredential{
		sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(map[string]any{
			"cnf":     map[string]any{"jwk": map[string]any{"x": "a"}},
			"status":  map[string]any{"status_list": map[string]any{"idx": float64(1), "uri": "https://example.com/sl"}},
			"_sd_alg": "sha-256",
		})),
		sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(map[string]any{
			"cnf":    map[string]any{"jwk": map[string]any{"x": "b"}},
			"status": map[string]any{"status_list": map[string]any{"idx": float64(2), "uri": "https://example.com/sl"}},
			"iat":    float64(1700000001),
			"jti":    "urn:uuid:2",
		})),
	})
	require.NoError(t, err)
}

func TestSdJwtVcCheckBatch_RejectsDifferingInstances(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		differing string
	}{
		{"claim value", map[string]any{"email": "bob@example.com"}, "email"},
		{"expiry", map[string]any{"exp": float64(1800000000)}, "exp"},
		{"not before", map[string]any{"nbf": float64(1700000001)}, "nbf"},
		{"claim only in one instance", map[string]any{"phone": "0612345678"}, "phone"},
		{"claim missing from one instance", map[string]any{"email": nil}, "email"},
	}
	parser := NewSdJwtVcCredentialFormatParser(nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := parser.CheckBatch([]*ParsedCredential{
				sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(nil)),
				sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(tc.overrides)),
			})
			require.ErrorContains(t, err, "credential 1 differs from credential 0 in "+tc.differing)
		})
	}
}

func TestSdJwtVcCheckBatch_RejectsInstancesFromDifferentIssuers(t *testing.T) {
	other := sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(nil))
	other.IssuerIdentifier = "https://other.example.com"

	err := NewSdJwtVcCredentialFormatParser(nil).CheckBatch([]*ParsedCredential{
		sdJwtVcBatchInstance(sdJwtVcBatchInstancePayload(nil)),
		other,
	})
	require.ErrorContains(t, err, "issued by")
}

func vcdmBatchInstance(subjectId, validFrom string, credentialStatus any, extra ...map[string]any) *ParsedCredential {
	payload := sdjwt.ProcessedPayload{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "EmailCredential"},
		"issuer":            batchInstanceTestIssuer,
		"validFrom":         validFrom,
		"credentialSubject": map[string]any{"id": subjectId, "email": "alice@example.com"},
	}
	if credentialStatus != nil {
		payload["credentialStatus"] = credentialStatus
	}
	for _, e := range extra {
		for key, value := range e {
			payload[key] = value
		}
	}
	return &ParsedCredential{
		Format:                   models.CredentialFormatSdJwtVcdm,
		VerifiableCredentialType: "EmailCredential",
		IssuerIdentifier:         batchInstanceTestIssuer,
		SdJwtVcdm:                &vcdmsdjwt.VerifiedSdJwtVcdm{ProcessedSdJwtPayload: payload},
	}
}

func TestSdJwtVcdmCheckBatch(t *testing.T) {
	parser := NewSdJwtVcdmCredentialFormatParser(nil)
	const validFrom = "2026-10-26T12:00:00Z"

	t.Run("instances may differ in their status entry", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmBatchInstance("did:key:a", validFrom, map[string]any{"statusListIndex": "1"}),
			vcdmBatchInstance("did:key:a", validFrom, map[string]any{"statusListIndex": "2"}),
		})
		require.NoError(t, err)
	})

	t.Run("instances may differ in their identifiers and issuance time", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmBatchInstance("did:key:a", validFrom, nil, map[string]any{"id": "urn:uuid:1", "jti": "urn:uuid:1", "iat": float64(1700000000)}),
			vcdmBatchInstance("did:key:a", validFrom, nil, map[string]any{"id": "urn:uuid:2", "jti": "urn:uuid:2", "iat": float64(1700000001)}),
		})
		require.NoError(t, err)
	})

	t.Run("instances may not differ in credentialSubject.id", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmBatchInstance("did:key:a", validFrom, nil),
			vcdmBatchInstance("did:key:b", validFrom, nil),
		})
		require.ErrorContains(t, err, "differs from credential 0 in credentialSubject")
	})

	t.Run("instances may not differ in validFrom", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			vcdmBatchInstance("did:key:a", validFrom, nil),
			vcdmBatchInstance("did:key:a", "2026-10-26T12:00:01Z", nil),
		})
		require.ErrorContains(t, err, "differs from credential 0 in validFrom")
	})
}

func mdocBatchInstance(thumbprint string, ageOver18 bool, validFrom time.Time) *ParsedCredential {
	return mdocBatchInstanceSignedAt(thumbprint, ageOver18, validFrom, validFrom)
}

func mdocBatchInstanceSignedAt(thumbprint string, ageOver18 bool, validFrom, signed time.Time) *ParsedCredential {
	return &ParsedCredential{
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: "eu.europa.ec.av.1",
		IssuerIdentifier:         batchInstanceTestIssuer,
		Mdoc: &ParsedMdoc{
			DocType:             "eu.europa.ec.av.1",
			Namespaces:          models.MdocNamespaces{"eu.europa.ec.av.1": {"age_over_18": ageOver18}},
			ValidityInfo:        mdoc.ValidityInfo{Signed: signed, ValidFrom: validFrom, ValidUntil: validFrom.Add(24 * time.Hour)},
			DeviceKeyThumbprint: thumbprint,
		},
	}
}

func TestMdocCheckBatch_RejectsDifferingInstances(t *testing.T) {
	parser := NewMdocCredentialFormatParser(nil)
	signed := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	t.Run("instances may differ in their device key", func(t *testing.T) {
		// The same instant in another zone is the same validity window.
		err := parser.CheckBatch([]*ParsedCredential{
			mdocBatchInstance("key-a", true, signed),
			mdocBatchInstance("key-b", true, signed.In(time.FixedZone("CET", 3600))),
		})
		require.NoError(t, err)
	})

	t.Run("instances may differ in their signing time", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			mdocBatchInstanceSignedAt("key-a", true, signed, signed),
			mdocBatchInstanceSignedAt("key-b", true, signed, signed.Add(time.Second)),
		})
		require.NoError(t, err)
	})

	t.Run("instances may not differ in an element value", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			mdocBatchInstance("key-a", true, signed),
			mdocBatchInstance("key-b", false, signed),
		})
		require.ErrorContains(t, err, "differs from credential 0 in namespaces")
	})

	t.Run("instances may not differ in their validity window", func(t *testing.T) {
		err := parser.CheckBatch([]*ParsedCredential{
			mdocBatchInstance("key-a", true, signed),
			mdocBatchInstance("key-b", true, signed.Add(time.Second)),
		})
		require.ErrorContains(t, err, "differs from credential 0 in validityInfo")
	})
}
