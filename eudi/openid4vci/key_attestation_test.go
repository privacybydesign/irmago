package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/metadata"
)

func TestSelectProofType(t *testing.T) {
	es256 := []string{"ES256"}
	required := &metadata.KeyAttestationRequirement{KeyStorage: []metadata.AttestationAttackResistance{metadata.Iso18045_High}}

	for name, tc := range map[string]struct {
		types       map[metadata.ProofTypeIdentifier]metadata.ProofType
		want        metadata.ProofTypeIdentifier
		requirement *metadata.KeyAttestationRequirement
		wantErr     string
	}{
		"jwt without key attestation": {
			types: map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: es256}},
			want:  metadata.ProofTypeIdentifier_JWT,
		},
		"jwt without key attestation wins over attestation": {
			types: map[metadata.ProofTypeIdentifier]metadata.ProofType{
				metadata.ProofTypeIdentifier_JWT:         {ProofSigningAlgValuesSupported: es256},
				metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: required},
			},
			want: metadata.ProofTypeIdentifier_JWT,
		},
		"attestation when a key attestation is required either way": {
			types: map[metadata.ProofTypeIdentifier]metadata.ProofType{
				metadata.ProofTypeIdentifier_JWT:         {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: required},
				metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: required},
			},
			want:        metadata.ProofTypeIdentifier_Attestation,
			requirement: required,
		},
		"attestation alone is a key attestation without constraints": {
			types:       map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: es256}},
			want:        metadata.ProofTypeIdentifier_Attestation,
			requirement: &metadata.KeyAttestationRequirement{},
		},
		"jwt with key attestation": {
			types:       map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: required}},
			want:        metadata.ProofTypeIdentifier_JWT,
			requirement: required,
		},
		"attestation not signable with ES256 falls back to jwt": {
			types: map[metadata.ProofTypeIdentifier]metadata.ProofType{
				metadata.ProofTypeIdentifier_JWT:         {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: required},
				metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: []string{"ES384"}},
			},
			want:        metadata.ProofTypeIdentifier_JWT,
			requirement: required,
		},
		"no ES256": {
			types:   map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: []string{"RS256"}}},
			wantErr: "only 'ES256'",
		},
		"no supported proof type": {
			types:   map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_DIVP: {ProofSigningAlgValuesSupported: es256}},
			wantErr: "no supported proof-type",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, requirement, err := selectProofType(tc.types)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.requirement, requirement)
		})
	}
}

func TestSatisfiesKeyAttestationRequirement(t *testing.T) {
	high := []metadata.AttestationAttackResistance{metadata.Iso18045_High}
	for name, tc := range map[string]struct {
		requirement        metadata.KeyAttestationRequirement
		keyStorage, userAu []string
		want               bool
	}{
		"no constraints":                  {want: true},
		"no constraints, nothing claimed": {keyStorage: nil, want: true},
		"key storage met":                 {requirement: metadata.KeyAttestationRequirement{KeyStorage: high}, keyStorage: []string{"iso_18045_high"}, want: true},
		"key storage not claimed":         {requirement: metadata.KeyAttestationRequirement{KeyStorage: high}},
		"key storage lower":               {requirement: metadata.KeyAttestationRequirement{KeyStorage: high}, keyStorage: []string{"iso_18045_moderate"}},
		"one of the accepted values":      {requirement: metadata.KeyAttestationRequirement{KeyStorage: []metadata.AttestationAttackResistance{metadata.Iso18045_Moderate, metadata.Iso18045_High}}, keyStorage: []string{"iso_18045_high"}, want: true},
		"both met":                        {requirement: metadata.KeyAttestationRequirement{KeyStorage: high, UserAuthentication: high}, keyStorage: []string{"iso_18045_high"}, userAu: []string{"iso_18045_high"}, want: true},
		"user authentication not met":     {requirement: metadata.KeyAttestationRequirement{KeyStorage: high, UserAuthentication: high}, keyStorage: []string{"iso_18045_high"}, userAu: []string{"iso_18045_basic"}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, satisfiesKeyAttestationRequirement(&tc.requirement, tc.keyStorage, tc.userAu))
		})
	}
}
