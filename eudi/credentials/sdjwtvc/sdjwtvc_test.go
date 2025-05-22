package sdjwtvc

import (
	"strings"
	"testing"
)

// is `iss` field is required
func TestNoIssuerLinkIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: DefaultVerifiableCredentialType,
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)

	if err == nil {
		t.Fatalf("expected error, but didn't get one")
	}
}

// the `iss` field of the issuer signed jwt is required to have a valid https link
func TestNoHttpsIssuerIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: DefaultVerifiableCredentialType,
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "http://invalid.com",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)

	if err == nil {
		t.Fatalf("expected error, but didn't get one")
	}
}

func TestIssuerSignedJwtPayloadToJson(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: DefaultVerifiableCredentialType,
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "https://example.com",
	}

	json, err := IssuerSignedJwtPayload_ToJson(payload)

	requireNoErr(t, err)

	values := jsonToMap(json)

	requirePresentWithValue(t, values, Key_Subject, "subject")
	requirePresentWithValue(t, values, Key_VerifiableCredentialType, DefaultVerifiableCredentialType)
	requirePresentWithValue(t, values, Key_Issuer, "https://example.com")
	requireNotPresent(t, values, Key_Sd)
	requireNotPresent(t, values, Key_SdAlg)
	requireNotPresent(t, values, Key_Confirmationkey)
}

func TestDisclosuresSaltBasicRequirements(t *testing.T) {
	numDisclosures := 1000
	// 128bit == 16 bytes, *4/3 for base64 encoding, rounded up == 22 characters
	expectedSaltLen := 22

	for range numDisclosures {
		disc, err := NewDisclosureContent("name", "Bert")
		requireNoErr(t, err)

		if len(disc.Salt) != expectedSaltLen {
			t.Fatalf("expected salt to be of len %v, but got %v (%s)", expectedSaltLen, len(disc.Salt), disc.Salt)
		}
	}
}

func TestCreateMultipleDisclosures(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"name":     "Yivi",
		"location": "Utrecht",
		"country":  "Netherlands",
	})

	requireNoErr(t, err)

	if num := len(disclosures); num != 3 {
		t.Fatalf("expected 3 disclosures, but got %v (%v)", num, disclosures)
	}
}

func TestCreateSdJwtVcWithSingleDisclosuresAndWithoutKbJwt(t *testing.T) {
	issuer := "https://example.com"
	disclosures, err := MultipleNewDisclosureContents(map[string]any{"family": "Yivi"})
	requireNoErr(t, err)

	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwt, err := CreateSdJwtVcForIssuance(issuer, disclosures, jwtCreator)
	requireNoErr(t, err)

	if !strings.HasSuffix(string(sdjwt), "~") {
		t.Fatalf("sdjwt expected to end with ~ but doesn't: %v", sdjwt)
	}

	if num := strings.Count(string(sdjwt), "~"); num != 2 {
		t.Fatalf("sdjwt expected have 2 ~ but has: %v (%v)", num, sdjwt)
	}
}

func TestCreateSdJwtVcIssuerReprWithDisclosures(t *testing.T) {
	issuer := "https://example.com"
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"family_name": "Yivi",
		"location":    "Utrecht",
	})
	requireNoErr(t, err)

	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdJwt, err := CreateSdJwtVc_IssuerRepresentation(issuer, disclosures, jwtCreator)
	requireNoErr(t, err)

	if num := len(sdJwt.Disclosures); num != 2 {
		t.Fatalf("expected num disclosures to be 2, but it was %v", num)
	}
}

func TestCreateSdJwtVcWithDisclosuresAndKbJwt(t *testing.T) {
	sdjwt := createDefaultTestingSdJwt(t)
	kbjwt := createKbJwtWithTestHolderKey(t, sdjwt)
	fullSdjwt := AddKeyBindingJwtToSdJwtVc(sdjwt, kbjwt)

	if numTildes := strings.Count(string(fullSdjwt), "~"); numTildes != 3 {
		t.Fatalf("expected 3 ~, but got %v (%v)", numTildes, fullSdjwt)
	}
}

func TestCreateSdJwtVcWithoutDisclosuresOrKbJwt(t *testing.T) {
	issuer := "https://example.com"
	disclosures := []DisclosureContent{}
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdJwt, err := CreateSdJwtVc_IssuerRepresentation(issuer, disclosures, jwtCreator)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sdJwt.Disclosures) != 0 {
		t.Fatal("sdjwt disclosured should be empty but is not")
	}

	if sdJwt.IssuerSignedJwt == "" {
		t.Fatalf("signed issuer jwt should not be empty but is")
	}

	if strings.HasSuffix(string(sdJwt.IssuerSignedJwt), "~") {
		t.Fatalf("signed issuer jwt should not end with ~")
	}
}
