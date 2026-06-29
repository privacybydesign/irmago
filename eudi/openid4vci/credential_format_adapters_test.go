package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestSdJwtCredentialFormatAdapter_VerifyCredentialInstances_ReturnsEnvelopes(t *testing.T) {
	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	require.NoError(t, err)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderJwkKey, err := jwk.Import(holderKey)
	require.NoError(t, err)

	testCredential, err := createTestSdJwtVcWithHolderKey(
		"test.credential.type",
		"https://test-issuer.example.com",
		map[string]string{"name": "Test User"},
		certChain,
		holderJwkKey,
	)
	require.NoError(t, err)

	adapter := &sdJwtCredentialFormatAdapter{
		holderVerifier: sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain)),
	}

	result, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: string(testCredential)}})
	require.NoError(t, err)
	require.Len(t, result.VerifiedSdJwtVcs, 1)
	require.Len(t, result.Envelopes, 1)
	require.Equal(t, string(metadata.CredentialFormatIdentifier_SdJwtVc), result.Envelopes[0].Format)
	require.Equal(t, "https://test-issuer.example.com", result.Envelopes[0].Issuer)
	require.NotNil(t, result.Envelopes[0].Claims)
	require.NotEmpty(t, result.Envelopes[0].RawCredential)
	require.NotEmpty(t, result.Envelopes[0].ID)
	raw, ok := result.Envelopes[0].RawCredential.(string)
	require.True(t, ok)
	require.NotEmpty(t, raw)
}

func TestSdJwtToEnvelope_MapsCoreFields(t *testing.T) {
	iat := int64(1712345678)
	exp := int64(1712349999)
	nbf := int64(1712345000)
	status := "https://issuer.example.com/status/123"

	vc := &sdjwtvc.VerifiedSdJwtVc{
		IssuerSignedJwtPayload: sdjwtvc.IssuerSignedJwtPayload{
			Issuer:                   "https://issuer.example.com",
			Subject:                  "did:example:holder",
			VerifiableCredentialType: "https://example.com/credentials/pid",
			Status:                   &status,
			IssuedAt:                 &iat,
			Expiry:                   &exp,
			NotBefore:                &nbf,
		},
		ProcessedSdJwtPayload: sdjwtvc.ProcessedSdJwtPayload{
			"name": "Alice",
		},
	}

	envelope := sdJwtToEnvelope(vc)
	require.NotNil(t, envelope)
	require.Equal(t, "https://issuer.example.com", envelope.Issuer)
	require.Equal(t, "did:example:holder", envelope.SubjectID)
	require.Equal(t, string(metadata.CredentialFormatIdentifier_SdJwtVc), envelope.Format)
	require.Equal(t, []string{"VerifiableCredential", "https://example.com/credentials/pid"}, envelope.Types)
	require.NotNil(t, envelope.Status)
	require.Equal(t, status, envelope.Status.ID)
	require.Empty(t, envelope.ID)
	require.Equal(t, time.Unix(iat, 0), *envelope.IssuanceDate)
	require.Equal(t, time.Unix(exp, 0), *envelope.ExpirationDate)
	require.Equal(t, time.Unix(nbf, 0), *envelope.ValidFrom)
	require.Equal(t, "Alice", envelope.Claims["name"])
}

func TestBuildEnvelopeID_Deterministic(t *testing.T) {
	id1 := buildEnvelopeID("abc.def.ghi")
	id2 := buildEnvelopeID("abc.def.ghi")
	id3 := buildEnvelopeID("xyz")

	require.Equal(t, id1, id2)
	require.NotEqual(t, id1, id3)
	require.Equal(t, "", buildEnvelopeID(""))
}

func TestJwtVcJsonCredentialFormatAdapter_ParseAndMap(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
		"iat": int64(1712345678),
		"exp": int64(1712349999),
		"jti": "urn:uuid:test-jti",
		"vc": map[string]any{
			"@context": []any{"https://www.w3.org/ns/credentials/v2"},
			"type":     []any{"VerifiableCredential", "ExampleCredential"},
			"credentialStatus": map[string]any{
				"id":   "https://issuer.example.com/status/1",
				"type": "StatusList2021Entry",
			},
		},
	}

	jwt := mustMakeTestJWT(t, header, payload)

	result, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.NoError(t, err)
	require.Nil(t, result.VerifiedSdJwtVcs)
	require.Len(t, result.Envelopes, 1)

	env := result.Envelopes[0]
	require.Equal(t, string(metadata.CredentialFormatIdentifier_W3CVC), env.Format)
	require.Equal(t, "urn:uuid:test-jti", env.ID)
	require.Equal(t, "https://issuer.example.com", env.Issuer)
	require.Equal(t, "did:example:alice", env.SubjectID)
	require.Equal(t, []string{"https://www.w3.org/ns/credentials/v2"}, env.Contexts)
	require.Contains(t, env.Types, "VerifiableCredential")
	require.Contains(t, env.Types, "ExampleCredential")
	require.NotNil(t, env.Status)
	require.Equal(t, "https://issuer.example.com/status/1", env.Status.ID)
	require.Equal(t, "StatusList2021Entry", env.Status.Type)
	require.Len(t, env.Proofs, 1)
	require.Equal(t, "JsonWebSignature2020", env.Proofs[0].Type)
	require.Equal(t, "ES256", env.Proofs[0].Cryptosuite)
	require.Equal(t, "assertionMethod", env.Proofs[0].ProofPurpose)
	require.Equal(t, "sig", env.Proofs[0].ProofValue)
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeRequiresKeyMaterial(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{"iss": "https://issuer.example.com", "sub": "did:example:alice"}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT key material (x5c)")
}

func TestJwtVcJsonCredentialFormatAdapter_DefaultModeAllowsNoKeyMaterial(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{"iss": "https://issuer.example.com", "sub": "did:example:alice"}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.NoError(t, err)
}

func TestJwtVcJsonCredentialFormatAdapter_RejectsAlgNone(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "none", "typ": "JWT"}
	payload := map[string]any{"iss": "https://issuer.example.com"}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"none\" is not allowed")
}

func TestJwtVcJsonCredentialFormatAdapter_RejectsHmacAlgWithX5c(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwt := mustMakeTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"HS256\" is not allowed with x5c")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeRejectsHmacAlgWithX5c(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true}

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwt := mustMakeTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"HS256\" is not allowed with x5c")
}

func TestJwtVcJsonCredentialFormatAdapter_RejectsUnsupportedAsymmetricAlgWithX5c(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{
		"alg": "ES256K",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwt := mustMakeTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT alg \"ES256K\" is not allowed with x5c")
}

func TestJwtVcJsonCredentialFormatAdapter_AllowsPs256WithX5c(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{
		"alg": "PS256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwt := mustMakeTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT signature")
}

func TestJwtVcJsonCredentialFormatAdapter_X5cSignatureVerified(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.NoError(t, err)
}

func TestJwtVcJsonCredentialFormatAdapter_X5cSignatureInvalid(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	valid := mustSignTestJWT(t, header, payload)
	invalid := mustCorruptJWTSignature(t, valid)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: invalid}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT signature")
}

func TestJwtVcJsonCredentialFormatAdapter_X5cChainValidated(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	leaf, parent, leafPriv := mustCreateX5cLeafAndParent(t)
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{leaf, parent},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.NoError(t, err)
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidX5cChainOrder(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	leaf, parent, leafPriv := mustCreateX5cLeafAndParent(t)
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{parent, leaf},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT x5c chain")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeTrustedX5cChain(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{
		strictSignatureVerification: true,
		x509VerificationContext:     &conf.Issuers,
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{leaf, root},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.NoError(t, err)
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeUntrustedX5cChainRejected(t *testing.T) {
	_, conf := mustCreateOpenID4vciConfigForAdapterTests(t)
	adapter := &jwtVcJsonCredentialFormatAdapter{
		strictSignatureVerification: true,
		x509VerificationContext:     &conf.Issuers,
	}

	leaf, parent, leafPriv := mustCreateX5cLeafAndParent(t)
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{leaf, parent},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT x5c certificate is not trusted")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeIssuerHostnameMismatchRejected(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{
		strictSignatureVerification: true,
		x509VerificationContext:     &conf.Issuers,
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{leaf, root},
	}
	payload := map[string]any{
		"iss": "https://wrong-issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: JWT x5c certificate is not trusted")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeIssuerInvalidURI(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{
		strictSignatureVerification: true,
		x509VerificationContext:     &conf.Issuers,
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{leaf, root},
	}
	payload := map[string]any{
		"iss": "not-a-uri",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid issuer URI for JWT x5c validation")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeMissingTrustConfiguration(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []any{mustLeafX5cB64FromPemChain(t, testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)},
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "did:example:alice",
	}

	jwsCompact := mustSignTestJWT(t, header, payload)
	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwsCompact}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT trust configuration")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidCompactFormat(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: "only-two.parts"}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid compact JWT format")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidHeaderEncoding(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	invalidHeader := "%"
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com"}`))

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", invalidHeader, payload)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT header encoding")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidHeaderJSON(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	invalidHeaderJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com"}`))

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", invalidHeaderJSON, payload)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT header JSON")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidPayloadEncoding(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	invalidPayload := "%"

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, invalidPayload)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT payload encoding")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidPayloadJSON(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	invalidPayloadJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, invalidPayloadJSON)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT payload JSON")
}

func TestJwtVcJsonCredentialFormatAdapter_MissingAlgHeader(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com"}`))

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, payload)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing JWT alg header")
}

func TestJwtVcJsonCredentialFormatAdapter_MissingIssuerClaim(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"did:example:alice"}`))

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: fmt.Sprintf("%s.%s.sig", header, payload)}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: missing issuer claim \"iss\"")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidX5cHeader(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": "not-an-array",
	}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
	}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid JWT x5c header")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidTemporalClaimType(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": "not-a-number",
	}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claim \"iat\"")
}

func TestJwtVcJsonCredentialFormatAdapter_InvalidTemporalClaimOrdering(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": int64(200),
		"exp": int64(100),
	}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: exp is before iat")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeExpiredTemporalClaim(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true, x509VerificationContext: &conf.Issuers}
	header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-10 * time.Minute).Unix(),
	}
	jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is expired")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeNbfInFuture(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true, x509VerificationContext: &conf.Issuers}
	header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(10 * time.Minute).Unix(),
	}
	jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is not yet valid")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeIatInFuture(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{strictSignatureVerification: true, x509VerificationContext: &conf.Issuers}
	header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": time.Now().Add(10 * time.Minute).Unix(),
	}
	jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: iat is in the future")
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeHonorsConfiguredTemporalClockSkew(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)

	t.Run("accepts credential expired within configured skew", func(t *testing.T) {
		adapter := &jwtVcJsonCredentialFormatAdapter{
			strictSignatureVerification: true,
			x509VerificationContext:     &conf.Issuers,
			temporalClockSkew:           30 * time.Minute,
		}

		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"exp": time.Now().Add(-10 * time.Minute).Unix(),
		}
		jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

		_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
		require.NoError(t, err)
	})

	t.Run("rejects credential expired outside configured skew", func(t *testing.T) {
		adapter := &jwtVcJsonCredentialFormatAdapter{
			strictSignatureVerification: true,
			x509VerificationContext:     &conf.Issuers,
			temporalClockSkew:           1 * time.Minute,
		}

		header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"exp": time.Now().Add(-3 * time.Minute).Unix(),
		}
		jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

		_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
		require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal claims: credential is expired")
	})
}

func TestJwtVcJsonCredentialFormatAdapter_StrictModeRejectsNegativeTemporalClockSkew(t *testing.T) {
	rootPem, root, leaf, leafPriv := mustCreateTrustedRootAndLeaf(t)
	conf := mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t, rootPem)
	adapter := &jwtVcJsonCredentialFormatAdapter{
		strictSignatureVerification: true,
		x509VerificationContext:     &conf.Issuers,
		temporalClockSkew:           -1 * time.Second,
	}

	header := map[string]any{"alg": "ES256", "typ": "JWT", "x5c": []any{leaf, root}}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	jwt := mustSignTestJWTWithPrivKey(t, header, payload, leafPriv)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.EqualError(t, err, "failed to parse jwt_vc_json credential: invalid temporal clock skew: must be non-negative")
}

func TestJwtVcJsonCredentialFormatAdapter_DefaultModeAllowsExpiredTemporalClaim(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-10 * time.Minute).Unix(),
	}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.NoError(t, err)
}

func TestJwtVcJsonCredentialFormatAdapter_DefaultModeAllowsNbfInFuture(t *testing.T) {
	adapter := &jwtVcJsonCredentialFormatAdapter{}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(10 * time.Minute).Unix(),
	}
	jwt := mustMakeTestJWT(t, header, payload)

	_, err := adapter.VerifyCredentialInstances([]CredentialInstance{{Credential: jwt}})
	require.NoError(t, err)
}

func TestValidateTemporalClaims_RejectsNegativeSkewInStrictMode(t *testing.T) {
	now := time.Now()
	exp := now.Add(10 * time.Minute)

	err := validateTemporalClaims(nil, nil, &exp, true, -1*time.Second)
	require.EqualError(t, err, "invalid temporal clock skew: must be non-negative")
}

func TestValidateTemporalClaims_NonStrictModeIgnoresNegativeSkew(t *testing.T) {
	now := time.Now()
	exp := now.Add(10 * time.Minute)

	err := validateTemporalClaims(nil, nil, &exp, false, -1*time.Second)
	require.NoError(t, err)
}

func Test_openid4vciSession_obtainCredential_jwtVcJsonAdapterSuccess(t *testing.T) {
	credEndpointHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		header := map[string]any{"alg": "ES256", "typ": "JWT"}
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"sub": "did:example:alice",
			"vc": map[string]any{
				"type": []any{"VerifiableCredential", "ExampleCredential"},
			},
		}

		resp, _ := json.Marshal(CredentialResponse{
			Credentials: []CredentialInstance{{Credential: mustMakeTestJWT(t, header, payload)}},
		})
		w.Write(resp)
	})

	session, ts := setupTestEnvironment(t, NonceNotRequired|CredentialConfigurationWithW3CVC, credEndpointHandler)
	defer ts.Close()

	fetched, err := session.obtainCredential("credential-config-1", nil, "test-token")
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Len(t, fetched.vcdmEnvelopes, 1)
	require.Equal(t, string(metadata.CredentialFormatIdentifier_W3CVC), fetched.vcdmEnvelopes[0].Format)
}

func mustMakeTestJWT(t *testing.T, header map[string]any, payload map[string]any) string {
	t.Helper()
	headJSON, err := json.Marshal(header)
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Signature bytes are irrelevant for current parser-level tests.
	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, "sig")
}

func mustSignTestJWT(t *testing.T, header map[string]any, payload map[string]any) string {
	t.Helper()

	privPem := testdata.IssuerPrivKeyBytes
	block, _ := pem.Decode(privPem)
	require.NotNil(t, block)

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	return mustSignTestJWTWithPrivKey(t, header, payload, priv)
}

func mustSignTestJWTWithPrivKey(t *testing.T, header map[string]any, payload map[string]any, priv *ecdsa.PrivateKey) string {
	t.Helper()

	tokBuilder := jwt.NewBuilder()
	for k, v := range payload {
		tokBuilder = tokBuilder.Claim(k, v)
	}
	tok, err := tokBuilder.Build()
	require.NoError(t, err)

	protected := jwsHeadersFromMap(header)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(protected)))
	require.NoError(t, err)

	return string(signed)
}

func jwsHeadersFromMap(m map[string]any) jws.Headers {
	b := jws.NewHeaders()
	for k, v := range m {
		switch k {
		case "alg":
			// Alg comes from the signing key option.
			continue
		case "typ":
			typ, _ := v.(string)
			_ = b.Set(jws.TypeKey, typ)
		case "x5c":
			if entries, ok := v.([]any); ok {
				x5cChain := &cert.Chain{}
				for _, e := range entries {
					if s, ok := e.(string); ok {
						err := x5cChain.Add([]byte(s))
						if err != nil {
							panic(err)
						}
					}
				}
				err := b.Set(jws.X509CertChainKey, x5cChain)
				if err != nil {
					panic(err)
				}
			}
		}
	}
	return b
}

func mustLeafX5cB64FromPemChain(t *testing.T, pemChain []byte) string {
	t.Helper()

	block, _ := pem.Decode(pemChain)
	require.NotNil(t, block)
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func mustCorruptJWTSignature(t *testing.T, compact string) string {
	t.Helper()

	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3)
	parts[2] = "AA"

	return strings.Join(parts, ".")
}

func mustCreateX5cLeafAndParent(t *testing.T) (leafB64 string, parentB64 string, leafPriv *ecdsa.PrivateKey) {
	t.Helper()

	parentPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	parentTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-parent"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentTemplate, parentTemplate, parentPriv.Public(), parentPriv)
	require.NoError(t, err)
	parentCert, err := x509.ParseCertificate(parentDER)
	require.NoError(t, err)

	leafPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, parentCert, leafPriv.Public(), parentPriv)
	require.NoError(t, err)

	leafB64 = base64.StdEncoding.EncodeToString(leafDER)
	parentB64 = base64.StdEncoding.EncodeToString(parentDER)
	return leafB64, parentB64, leafPriv
}

func mustCreateOpenID4vciConfigForAdapterTests(t *testing.T) (storage.Storage, *eudi.Configuration) {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err := common.CopyDirectory(filepath.Join(testStoragePath, "eudi"), eudiAppDataPath)
	require.NoError(t, err)

	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	conf.EnableStrictJwtVcJsonVerification()

	return s, conf
}

func mustCreateOpenID4vciConfigWithIssuerTrustAnchor(t *testing.T, issuerTrustAnchorPem []byte) *eudi.Configuration {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err := common.CopyDirectory(filepath.Join(testStoragePath, "eudi"), eudiAppDataPath)
	require.NoError(t, err)

	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	require.NoError(t, conf.Issuers.InstallCertificate(issuerTrustAnchorPem))
	require.NoError(t, conf.Reload())

	conf.EnableStrictJwtVcJsonVerification()

	return conf
}

func mustCreateTrustedRootAndLeaf(t *testing.T) (rootPem []byte, rootB64 string, leafB64 string, leafPriv *ecdsa.PrivateKey) {
	t.Helper()

	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPriv.Public(), rootPriv)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"issuer.example.com"},
		URIs: func() []*url.URL {
			u, err := url.Parse("https://issuer.example.com")
			require.NoError(t, err)
			return []*url.URL{u}
		}(),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, leafPriv.Public(), rootPriv)
	require.NoError(t, err)

	rootB64 = base64.StdEncoding.EncodeToString(rootDER)
	leafB64 = base64.StdEncoding.EncodeToString(leafDER)
	rootPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	return rootPem, rootB64, leafB64, leafPriv
}
