package zk

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The timestamp format and the width the C ABI reads have to agree. They are
// two constants describing one thing, and a proof taken over a differently
// formatted instant is a proof of a different statement.
func TestTimestampFormatIsExactlyTheWidthTheABIReads(t *testing.T) {
	formatted := FormatTimestamp(time.Date(2023, 11, 2, 9, 0, 0, 0, time.UTC))
	require.Equal(t, "2023-11-02T09:00:00Z", formatted)
	require.Len(t, formatted, TimestampLen)
}

func TestFormatTimestampDropsSubSecondsAndConvertsToUTC(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tzdata on this machine")
	}

	// 10:30:45.999 in Berlin (UTC+1 in January) is 09:30:45 UTC once the
	// fractional part is dropped rather than rounded.
	local := time.Date(2024, 1, 15, 10, 30, 45, 999_000_000, berlin)
	require.Equal(t, "2024-01-15T09:30:45Z", FormatTimestamp(local))
	require.Len(t, FormatTimestamp(local), TimestampLen)
}

// The fixed widths are refused, not truncated. Google's own set_attribute
// clamps an over-long value silently, which would produce a perfectly valid
// proof about a value nobody asked about.
func TestAttributeValidateRefusesOverlongFieldsRatherThanTruncating(t *testing.T) {
	good := Attribute{Namespace: "org.iso.18013.5.1", Identifier: "age_over_18", Value: []byte{0xf5}}
	require.NoError(t, good.Validate())

	tests := map[string]Attribute{
		"namespace too long": {
			Namespace:  strings.Repeat("n", MaxNamespaceLen+1),
			Identifier: "age_over_18",
			Value:      []byte{0xf5},
		},
		"identifier too long": {
			Namespace:  "org.iso.18013.5.1",
			Identifier: strings.Repeat("i", MaxIdentifierLen+1),
			Value:      []byte{0xf5},
		},
		"value too long": {
			Namespace:  "org.iso.18013.5.1",
			Identifier: "age_over_18",
			Value:      make([]byte, MaxValueLen+1),
		},
		"no namespace":  {Identifier: "age_over_18", Value: []byte{0xf5}},
		"no identifier": {Namespace: "org.iso.18013.5.1", Value: []byte{0xf5}},
		"no value":      {Namespace: "org.iso.18013.5.1", Identifier: "age_over_18"},
	}
	for name, attribute := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, attribute.Validate())
		})
	}
}

// Exactly at the limit is allowed; the limits are inclusive because the C
// struct's fields are that wide.
func TestAttributeValidateAllowsExactlyTheLimit(t *testing.T) {
	attribute := Attribute{
		Namespace:  strings.Repeat("n", MaxNamespaceLen),
		Identifier: strings.Repeat("i", MaxIdentifierLen),
		Value:      make([]byte, MaxValueLen),
	}
	require.NoError(t, attribute.Validate())
}

func validProofRequest() ProofRequest {
	return ProofRequest{
		Circuit:        "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		DocType:        "eu.europa.ec.av.1",
		DeviceResponse: []byte{0x01},
		IssuerKeyX:     "0x" + strings.Repeat("a", 64),
		IssuerKeyY:     "0x" + strings.Repeat("b", 64),
		Transcript:     []byte{0x02},
		Attributes: []Attribute{
			{Namespace: "eu.europa.ec.av.1", Identifier: "age_over_18", Value: []byte{0xf5}},
		},
		Timestamp: time.Now(),
	}
}

func TestProofRequestValidateAcceptsACompleteRequest(t *testing.T) {
	require.NoError(t, validProofRequest().Validate())
}

func TestProofRequestValidateNamesWhatIsMissing(t *testing.T) {
	tests := map[string]func(*ProofRequest){
		"no circuit":        func(r *ProofRequest) { r.Circuit = "" },
		"no docType":        func(r *ProofRequest) { r.DocType = "" },
		"no DeviceResponse": func(r *ProofRequest) { r.DeviceResponse = nil },
		"no transcript":     func(r *ProofRequest) { r.Transcript = nil },
		"no attributes":     func(r *ProofRequest) { r.Attributes = nil },
		"bad attribute":     func(r *ProofRequest) { r.Attributes[0].Value = nil },
	}
	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			request := validProofRequest()
			break_(&request)
			require.Error(t, request.Validate())
		})
	}
}

// A coordinate of the wrong width is the failure that would otherwise become a
// proof about a key nobody holds: the ABI reads a fixed number of hex
// characters, so a short coordinate silently shifts everything after it.
func TestProofRequestValidateRefusesMisshapenKeyCoordinates(t *testing.T) {
	tests := map[string]string{
		"empty":         "",
		"no 0x prefix":  strings.Repeat("a", 66),
		"too short":     "0x" + strings.Repeat("a", 62),
		"too long":      "0x" + strings.Repeat("a", 66),
		"unpadded zero": "0x0",
	}
	for name, coordinate := range tests {
		t.Run("x "+name, func(t *testing.T) {
			request := validProofRequest()
			request.IssuerKeyX = coordinate
			require.Error(t, request.Validate())
		})
		t.Run("y "+name, func(t *testing.T) {
			request := validProofRequest()
			request.IssuerKeyY = coordinate
			require.Error(t, request.Validate())
		})
	}
}

func TestVerificationRequestValidate(t *testing.T) {
	valid := VerificationRequest{
		Circuit:    "137e5a75",
		DocType:    "eu.europa.ec.av.1",
		IssuerKeyX: "0x" + strings.Repeat("a", 64),
		IssuerKeyY: "0x" + strings.Repeat("b", 64),
		Transcript: []byte{0x02},
		Attributes: []Attribute{
			{Namespace: "eu.europa.ec.av.1", Identifier: "age_over_18", Value: []byte{0xf5}},
		},
		Proof: []byte{0x03},
	}
	require.NoError(t, valid.Validate())

	tests := map[string]func(*VerificationRequest){
		"no circuit":    func(r *VerificationRequest) { r.Circuit = "" },
		"no docType":    func(r *VerificationRequest) { r.DocType = "" },
		"no transcript": func(r *VerificationRequest) { r.Transcript = nil },
		"no proof":      func(r *VerificationRequest) { r.Proof = nil },
		"no attributes": func(r *VerificationRequest) { r.Attributes = nil },
		"bad key":       func(r *VerificationRequest) { r.IssuerKeyX = "nonsense" },
	}
	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			request := valid
			break_(&request)
			require.Error(t, request.Validate())
		})
	}
}
