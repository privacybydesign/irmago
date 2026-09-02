package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// SeedSdJwtVcForTesting stores an SD-JWT VC in the wallet's EUDI credential
// store as if the given credential issuer had just issued it, bypassing the
// OpenID4VCI flow: a seeded credential, in the integration tests' vocabulary.
//
// The credential's signature is verified, and its issuer certificate must be
// valid and unrevoked, but it need not chain to an anchor: what the wallet makes
// of the issuer is the trust ladder's question, which is what tests seeding
// credentials are about. The credential is stored without a holder binding key,
// so a disclosure of it needs a query that does not require cryptographic
// holder binding.
//
// For tests only. Nothing in a released wallet calls it.
func (client *Client) SeedSdJwtVcForTesting(rawSdJwtVc string, issuerMetadata metadata.CredentialIssuerMetadata, credentialConfigurationId string) error {
	processor := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &client.openid4vpClient.Configuration.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
		AcceptUnanchoredIssuers: true,
	})
	processor.SetAllowInsecureDidWeb(true)
	verified, err := processor.ParseAndVerifySdJwtVc(sdjwtvc.SdJwtVcKb(rawSdJwtVc))
	if err != nil {
		return fmt.Errorf("seed credential: %w", err)
	}
	return client.credentialService.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{verified}, credentialConfigurationId, issuerMetadata, false, nil)
}
