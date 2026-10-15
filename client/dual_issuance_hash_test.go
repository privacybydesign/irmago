package client

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

// Dual issuance over IRMA gives the wallet one idemix credential and a batch of
// SD-JWTs for the same credential request. The wallet merges the two into one
// credential by comparing hashAttributesAndCredType on both sides. These tests
// build both sides through the same code the wallet uses, starting from one
// CredentialRequest, and check that the hashes match.

func loadTestIrmaConfiguration(t *testing.T) *irma.Configuration {
	conf, err := irma.NewConfiguration(test.FindTestdataFolder(t)+"/irma_configuration", irma.ConfigurationOptions{})
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())
	return conf
}

// idemixCredentialInfo builds the CredentialInfo the wallet gets for the idemix
// side: request -> attribute list (big ints) -> decoded CredentialInfo.
func idemixCredentialInfo(t *testing.T, conf *irma.Configuration, req *irma.CredentialRequest) *irma.CredentialInfo {
	al, err := req.AttributeList(conf, 0x03, nil, time.Now())
	require.NoError(t, err)
	return al.CredentialInfo()
}

// sdJwtCredentialInfo builds the CredentialInfo the wallet gets for the SD-JWT
// side. The server makes one SD claim per entry in req.Attributes
// (generateSdJwts), and the wallet reads the disclosures back into a map
// (createCredentialInfoAndVerifiedSdJwtVc). So the attribute map is exactly
// req.Attributes.
func sdJwtCredentialInfo(req *irma.CredentialRequest) *irma.CredentialInfo {
	attrs := map[string]any{}
	for k, v := range req.Attributes {
		attrs[k] = v
	}
	return sdjwtvcBatchMetadataToIrmaCredentialInfo(irmaclient.SdJwtVcBatchMetadata{
		CredentialType:         req.CredentialTypeID.String(),
		Attributes:             attrs,
		Hash:                   "sdjwt-storage-hash",
		RemainingInstanceCount: 10,
	})
}

func fullNameRequest(attrs map[string]string) *irma.CredentialRequest {
	return &irma.CredentialRequest{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes:       attrs,
	}
}

func TestDualIssuanceHash_AllAttributesPresent(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	req := fullNameRequest(map[string]string{
		"firstnames": "Barry",
		"firstname":  "Bar",
		"familyname": "Batsbak",
		"prefix":     "Sir",
	})

	idemixHash, err := hashAttributesAndCredType(idemixCredentialInfo(t, conf, req))
	require.NoError(t, err)
	sdJwtHash, err := hashAttributesAndCredType(sdJwtCredentialInfo(req))
	require.NoError(t, err)

	require.Equal(t, idemixHash, sdJwtHash)
}

// An optional attribute set to "" is still sent as an SD claim, and idemix
// (metadata version >= 3) decodes it back to "". Both sides agree.
func TestDualIssuanceHash_OptionalAttributeEmptyString(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	req := fullNameRequest(map[string]string{
		"firstnames": "Barry",
		"firstname":  "Bar",
		"familyname": "Batsbak",
		"prefix":     "",
	})

	idemixHash, err := hashAttributesAndCredType(idemixCredentialInfo(t, conf, req))
	require.NoError(t, err)
	sdJwtHash, err := hashAttributesAndCredType(sdJwtCredentialInfo(req))
	require.NoError(t, err)

	require.Equal(t, idemixHash, sdJwtHash)
}

// An optional attribute left out of the request. Idemix keeps the key with
// a nil value (it hashes as `...prefix` + `null`); the SD-JWT has no claim for
// it, so the key is missing from the map. The hash must ignore the nil value.
func TestDualIssuanceHash_OptionalAttributeAbsent(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	req := fullNameRequest(map[string]string{
		"firstnames": "Barry",
		"firstname":  "Bar",
		"familyname": "Batsbak",
	})

	idemix := idemixCredentialInfo(t, conf, req)
	sdJwt := sdJwtCredentialInfo(req)

	prefix := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.prefix")
	_, inIdemix := idemix.Attributes[prefix]
	_, inSdJwt := sdJwt.Attributes[prefix]
	require.True(t, inIdemix, "idemix lists the absent optional attribute (with a nil value)")
	require.False(t, inSdJwt, "the SD-JWT has no claim for the absent optional attribute")

	idemixHash, err := hashAttributesAndCredType(idemix)
	require.NoError(t, err)
	sdJwtHash, err := hashAttributesAndCredType(sdJwt)
	require.NoError(t, err)

	require.Equal(t, idemixHash, sdJwtHash)
}

// Without that, GetCredentials would show the credential twice,
// once per format, instead of one card holding both formats.
func TestDualIssuance_OptionalAttributeAbsent_MergesIntoOneCredential(t *testing.T) {
	conf := loadTestIrmaConfiguration(t)
	req := fullNameRequest(map[string]string{
		"firstnames": "Barry",
		"firstname":  "Bar",
		"familyname": "Batsbak",
	})

	creds, problematic := credentialInfoListToSchemaless(conf, irma.CredentialInfoList{
		idemixCredentialInfo(t, conf, req),
		sdJwtCredentialInfo(req),
	}, "en")

	require.Empty(t, problematic)
	require.Len(t, creds, 1, "idemix and SD-JWT copies should merge into one credential")
	require.Len(t, creds[0].CredentialInstanceIds, 2)
	require.Contains(t, creds[0].CredentialInstanceIds, clientmodels.Format_Idemix)
	require.Contains(t, creds[0].CredentialInstanceIds, clientmodels.Format_SdJwtVc)
}
