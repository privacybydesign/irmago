package sdjwtvc

import (
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestHolderParsing(t *testing.T) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim("iat", 13853353),
			Claim("vct", "pbdf.sidn-pbdf.email"),
			Claim("iss", "https://irma.app"),
			Claim(Key_SdAlg, iana.SHA256),
			SdObject("address",
				SdClaim("street", "Schulstr 3"),
				SdClaim("country", "Germany"),
				// SdClaim("null", Null{}),
			),
			Object("personal_data",
				SdClaim("first_name", "Gerrit"),
				SdClaim("last_name", "Dijkstra"),
			),
			Array("nationalities", SdItem("NL"), SdItem("FR")),
		).
		WithIssuerCertificateChain(irmaAppCert).
		Build(jwtCreator)

	require.NoError(t, err)

	parsed, err := Parse(sdJwt)
	require.NoError(t, err)
	require.NotNil(t, parsed.Claims)

	d, err := parsed.CreateDisclosure([][]any{
		{"address", "country"},
		{"personal_data", "last_name"},
		{"nationalities", nil},
	})

	require.NoError(t, err)
	fmt.Printf("sdjwt:\n%v\n", d)
}
