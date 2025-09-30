package testdata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mathRand "math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// For more details on these values check `testdata/eudi/readme.md`.

//go:embed eudi/holder_ec_priv.pem
var HolderPrivKeyBytes []byte

//go:embed eudi/holder_ec_pub.jwk
var HolderPubJwkBytes []byte

//go:embed eudi/issuer_ec_priv.pem
var IssuerPrivKeyBytes []byte

//go:embed eudi/issuer_ec_pub.jwk
var IssuerPubJwkBytes []byte

//go:embed eudi/issuer_cert_openid4vc_staging_yivi_app.pem
var IssuerCert_openid4vc_staging_yivi_app_Bytes []byte

//go:embed eudi/issuer_cert_irma_app.pem
var IssuerCert_irma_app_Bytes []byte

//go:embed eudi/issuer_cert_chain_irma_app.pem
var IssuerCertChain_irma_app_Bytes []byte

//go:embed eudi/verifier/verifier_scheme_data.json
var VerifierCertSchemeData string

type PkiGenerationOptions int

const (
	PkiOption_None                  PkiGenerationOptions = 1
	PkiOption_ExpiredEndEntity      PkiGenerationOptions = 2
	PkiOption_RevokedEndEntity      PkiGenerationOptions = 4
	PkiOption_ExpiredIntermediate   PkiGenerationOptions = 8
	PkiOption_RevokedIntermediates  PkiGenerationOptions = 16
	PkiOption_ExpiredRoot           PkiGenerationOptions = 32
	PkiOption_MissingSchemeData     PkiGenerationOptions = 64
	PkiOption_InvalidAsnSchemeData  PkiGenerationOptions = 128
	PkiOption_InvalidJsonSchemeData PkiGenerationOptions = 256
)

func ParseHolderPubJwk() jwk.Key {
	key, err := jwk.ParseKey(HolderPubJwkBytes)
	if err != nil {
		log.Fatalf("failed to parse holder pub key jwk: %v", err)
	}
	return key
}

func ParseIssuerPubJwk() jwk.Key {
	key, err := jwk.ParseKey(IssuerPubJwkBytes)
	if err != nil {
		log.Fatalf("failed to parse issuer pub key jwk: %v", err)
	}
	return key
}

func CreateTestAuthorizationRequestRequest(issuerCert []byte) string {
	return fmt.Sprintf(`
{
  "type": "vp_token",  
  "dcql_query": {
    "credentials": [
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["test.test.email"]
        },
        "claims": [
          {
			"path": ["email"]
          }
        ]
      },
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["test.test.mobilephone"]
        },
        "claims": [
          {
			"path": ["mobilephone"]
          }
        ]
      }
    ]
  },
  "nonce": "nonce",
  "jar_mode": "by_reference",
  "request_uri_method": "post",
  "issuer_chain": "%s"
}
`,
		string(issuerCert),
	)
}

func CreateTestAuthorizationRequestJWT(hostname string, verifierKey *ecdsa.PrivateKey, verifierCert *x509.Certificate, modifyTokenFunc func(token *jwt.Token)) string {
	authReq := openid4vp.AuthorizationRequest{
		Audience: "https://audience",
		ClientId: "x509_san_dns:" + hostname,
		DcqlQuery: dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{
				{
					Id:     "32f54163-7166-48f1-93d8-ff217bdb0653",
					Format: "dc+sd-jwt",
					Claims: []dcql.Claim{
						{
							Path: []string{"email"},
						},
					},
				},
			},
		},
		Nonce:        "nonce",
		ResponseMode: openid4vp.ResponseMode_DirectPost,
		ResponseType: string(openid4vp.ResponseType_VpToken),
		ResponseUri:  "https://response.uri",
		RedirectUri:  "https://redirect.uri",
		State:        "state",
	}

	authReqBytes, _ := json.Marshal(authReq)

	var c jwt.MapClaims
	json.Unmarshal(authReqBytes, &c)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	token.Header["typ"] = openid4vp.AuthRequestJwtTyp
	token.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(verifierCert.Raw)}

	if modifyTokenFunc != nil {
		modifyTokenFunc(token)
	}

	authRequestJwt, _ := token.SignedString(verifierKey)
	return authRequestJwt
}

func CreateTestPkiHierarchy(t *testing.T, rootName pkix.Name, numberOfCAs int, opts PkiGenerationOptions, crlDistPoint *string) (
	rootKey *ecdsa.PrivateKey,
	rootCert *x509.Certificate,
	caKeys []*ecdsa.PrivateKey,
	caCerts []*x509.Certificate,
	caCrls []*x509.RevocationList,
) {
	rootKey, rootCert = CreateRootCertificate(t, rootName, opts)

	caKeys = make([]*ecdsa.PrivateKey, numberOfCAs)
	caCerts = make([]*x509.Certificate, numberOfCAs)
	caCrls = make([]*x509.RevocationList, numberOfCAs)

	for i := range numberOfCAs {
		caKey, caCert, caCrl := CreateCaCertificate(t, CreateDistinguishedName("CA CERT "+strconv.Itoa(i)), rootCert, rootKey, opts, crlDistPoint)
		caKeys[i] = caKey
		caCerts[i] = caCert
		caCrls[i] = caCrl
	}

	return
}

func CreateRootCertificate(t *testing.T, subject pkix.Name, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a self-signed root certificate
	keyId := generateRandomBytes(10)
	certTemplate := getCaCertTemplate(keyId, keyId, subject, opts, nil)

	if opts&PkiOption_ExpiredRoot != 0 {
		certTemplate.NotAfter = time.Now().Add(-time.Hour)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return
}

func CreateCaCertificate(t *testing.T, subject pkix.Name, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, opts PkiGenerationOptions, crlDistPoint *string) (key *ecdsa.PrivateKey, cert *x509.Certificate, parentCrl *x509.RevocationList) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the CA certificate
	keyId := generateRandomBytes(10)
	certTemplate := getCaCertTemplate(rootCert.AuthorityKeyId, keyId, subject, opts, crlDistPoint)

	if opts&PkiOption_ExpiredIntermediate != 0 {
		certTemplate.NotAfter = time.Now().Add(-time.Hour)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, key.Public(), rootKey)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Create a CRL for the CA
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(time.Duration(-1 * time.Hour)),
		NextUpdate: time.Now().Add(time.Duration(1 * time.Hour)),
	}

	if opts&PkiOption_RevokedIntermediates != 0 {
		crlTemplate.RevokedCertificateEntries = []x509.RevocationListEntry{
			{
				SerialNumber:   cert.SerialNumber,
				RevocationTime: time.Now().Add(-time.Hour),
				ReasonCode:     0,
			},
		}
	}

	parentCrlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, rootCert, rootKey)
	require.NoError(t, err)
	parentCrl, err = x509.ParseRevocationList(parentCrlBytes)
	require.NoError(t, err)
	return
}

func CreateEndEntityCertificate(t *testing.T, subject pkix.Name, hostname string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, schemeData string, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate, certDerBytes []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the SAN URI (in case of issuer certificate)
	uri := &url.URL{
		Scheme: "https",
		Host:   hostname,
	}

	// Create the end entity certificate
	asn1SchemeData, _ := asn1.Marshal(schemeData)
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(mathRand.Int63()),
		Subject:               subject,
		SubjectKeyId:          generateRandomBytes(10),
		KeyUsage:              x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             time.Now().Add(time.Duration(-1 * time.Hour)),
		NotAfter:              time.Now().Add(time.Duration(1 * time.Hour)),
		DNSNames:              []string{hostname},
		URIs:                  []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    stringToObjectIdentifier("2.1.123.1"),
				Value: asn1SchemeData,
			},
		},
	}

	if opts&PkiOption_InvalidAsnSchemeData != 0 {
		certTemplate.ExtraExtensions[0].Value = []byte("invalid ASN scheme data")
	}

	if opts&PkiOption_InvalidJsonSchemeData != 0 {
		asn1SchemeData, _ := asn1.Marshal("invalid JSON scheme data")
		certTemplate.ExtraExtensions[0].Value = asn1SchemeData
	}

	if opts&PkiOption_MissingSchemeData != 0 {
		certTemplate.ExtraExtensions = []pkix.Extension{}
	}

	certDerBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, key.Public(), caKey)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certDerBytes)
	require.NoError(t, err)

	return
}

func CreateDistinguishedName(cn string) pkix.Name {
	return pkix.Name{
		Country:            []string{"NL"},
		Organization:       []string{"Test Organization"},
		OrganizationalUnit: []string{"Test Unit"},
		CommonName:         cn,
	}
}

func getCaCertTemplate(authKeyId []byte, subKeyId []byte, subject pkix.Name, opts PkiGenerationOptions, crlDistPoint *string) *x509.Certificate {
	certTemplate := &x509.Certificate{
		AuthorityKeyId:        authKeyId,
		SerialNumber:          big.NewInt(mathRand.Int63()),
		Subject:               subject,
		SubjectKeyId:          subKeyId,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(time.Duration(-1 * time.Hour)),
		NotAfter:              time.Now().Add(time.Duration(1 * time.Hour)),
	}

	if crlDistPoint != nil {
		certTemplate.CRLDistributionPoints = []string{*crlDistPoint}
	}

	return certTemplate
}

func GetDefaultCrlTemplate(cert *x509.Certificate) *x509.RevocationList {
	return &x509.RevocationList{
		Number:         big.NewInt(1),
		ThisUpdate:     time.Now().Add(-time.Hour),
		NextUpdate:     time.Now().Add(time.Hour),
		AuthorityKeyId: cert.AuthorityKeyId,
	}
}

func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return bytes
}

func stringToObjectIdentifier(oidStr string) asn1.ObjectIdentifier {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))

	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			panic(fmt.Errorf("invalid OID component: %v", err))
		}
		oid[i] = num
	}

	return oid
}

const (
	// Eudi verifier server with direct_post as the response_mode
	OpenID4VP_DirectPost_Host = "http://127.0.0.1:8089"

	// Eudi verifier server with direct_post.jwt as the response_mode
	OpenID4VP_DirectPostJwt_Host = "http://127.0.0.1:8090"
)

func WriteCertAsPemFile(t *testing.T, path string, certs ...*x509.Certificate) {
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		err = pem.Encode(file, pemBlock)
	}
	require.NoError(t, err)
}

func WritePrivateKeyToFile(t *testing.T, path string, key *ecdsa.PrivateKey) {
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	b, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}
	err = pem.Encode(file, pemBlock)
	require.NoError(t, err)
}
