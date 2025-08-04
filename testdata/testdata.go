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
	"fmt"
	"log"
	"math/big"
	mathRand "math/rand"
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

//go:embed eudi/verifier/verifier.crt
var VerifierCert_localhost_Bytes []byte

//go:embed eudi/verifier/verifier_scheme_data.json
var VerifierCertSchemeData string

type PkiGenerationOptions int

const (
	PkiOption_None                  PkiGenerationOptions = iota
	PkiOption_ExpiredEndEntity                           = 2
	PkiOption_RevokedEndEntity                           = 4
	PkiOption_ExpiredIntermediate                        = 8
	PkiOption_RevokedIntermediates                       = 16
	PkiOption_ExpiredRoot                                = 32
	PkiOption_MissingSchemeData                          = 64
	PkiOption_InvalidAsnSchemeData                       = 128
	PkiOption_InvalidJsonSchemeData                      = 256
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
			"vct_values": ["pbdf.sidn-pbdf.email"]
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
			"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]
        },
        "claims": [
          {
			"path": ["mobilenumber"]
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

func CreateTestPkiHierarchy(t *testing.T, rootName pkix.Name, numberOfCAs int, opts PkiGenerationOptions) (
	rootKey *ecdsa.PrivateKey,
	rootCert *x509.Certificate,
	rootCrl *x509.RevocationList,
	caKeys []*ecdsa.PrivateKey,
	caCerts []*x509.Certificate,
	caCrls []*x509.RevocationList,
) {
	rootKey, rootCert = CreateRootCertificate(t, rootName, opts)

	caKeys = make([]*ecdsa.PrivateKey, numberOfCAs)
	caCerts = make([]*x509.Certificate, numberOfCAs)
	caCrls = make([]*x509.RevocationList, numberOfCAs)

	for i := range numberOfCAs {
		caKey, caCert, caCrl := CreateCaCertificate(t, CreateDistinguishedName("CA CERT "+strconv.Itoa(i)), rootCert, rootKey, opts)
		caKeys[i] = caKey
		caCerts[i] = caCert
		caCrls[i] = caCrl
	}

	rootCrl = CreateRootRevocationList(t, rootKey, rootCert, caCerts, opts)

	return
}

func CreateRootCertificate(t *testing.T, subject pkix.Name, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a self-signed root certificate
	certTemplate := getCaCertTemplate(subject, opts)

	if opts&PkiOption_ExpiredRoot != 0 {
		certTemplate.NotAfter = time.Now().Add(-time.Hour)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return
}

func CreateRootRevocationList(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate, revokedCerts []*x509.Certificate, opts PkiGenerationOptions) (crl *x509.RevocationList) {
	// Create revocation list for the root certificate
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}

	// Add all CA certs to the CRL (no option to select just one for now)
	if opts&PkiOption_RevokedIntermediates != 0 {
		revokedIntermediateEntries := make([]x509.RevocationListEntry, 0, len(revokedCerts))
		for _, caCert := range revokedCerts {
			revokedIntermediateEntries = append(revokedIntermediateEntries, x509.RevocationListEntry{
				SerialNumber:   caCert.SerialNumber,
				RevocationTime: time.Now().Add(-time.Hour),
				ReasonCode:     0,
			})
		}
		crlTemplate.RevokedCertificateEntries = revokedIntermediateEntries
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)

	return
}

func CreateRootCertificateWithEmptyRevocationList(t *testing.T, subject pkix.Name, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate, crl *x509.RevocationList) {
	key, cert = CreateRootCertificate(t, subject, opts)
	crl = CreateRootRevocationList(t, key, cert, nil, opts)
	return
}

func CreateCaCertificate(t *testing.T, subject pkix.Name, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate, crl *x509.RevocationList) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the CA certificate
	certTemplate := getCaCertTemplate(subject, opts)

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
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)
	return
}

func CreateEndEntityCertificate(t *testing.T, subject pkix.Name, hostname string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, opts PkiGenerationOptions) (key *ecdsa.PrivateKey, cert *x509.Certificate, certDerBytes []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the end entity certificate
	asn1SchemeData, _ := asn1.Marshal(VerifierCertSchemeData)
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

func getCaCertTemplate(subject pkix.Name, opts PkiGenerationOptions) *x509.Certificate {
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(mathRand.Int63()),
		Subject:               subject,
		SubjectKeyId:          generateRandomBytes(10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(time.Duration(-1 * time.Hour)),
		NotAfter:              time.Now().Add(time.Duration(1 * time.Hour)),
	}

	return certTemplate
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
