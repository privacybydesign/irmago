package sdjwtvc

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ParsePemCertificateChain takes in the raw contents of a PEM formatted certificate
// file and returns the contents as a list of x509 certificates.
func ParsePemCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// ParseCertificateChain takes in the raw contents of a PEM formatted certificate
// file and returns the contents of the chain in the format expected
// as the `x5c` header parameter of a jwt.
func ParseCertificateChain(data []byte) ([]string, error) {
	certs, err := ParsePemCertificateChain(data)
	if err != nil {
		return nil, err
	}

	x5c := []string{}

	for _, cert := range certs {
		encoded := base64.StdEncoding.EncodeToString(cert.Raw)
		x5c = append(x5c, encoded)
	}

	return x5c, nil
}

type SdJwtVcBuilder struct {
	issuerCertificateChain *[]string
	lifetime               *int64
	issuerUrl              *string
	allowNonHttps          bool
	cnfPubKey              *CnfField
	status                 *string
	subject                *string
	vct                    *string
	sdAlg                  *HashingAlgorithm
	disclosures            []DisclosureContent
	clock                  *Clock
	ensureHaipCompatible   bool
}

func NewSdJwtVcBuilder() *SdJwtVcBuilder {
	return &SdJwtVcBuilder{}
}

func (b *SdJwtVcBuilder) WithIssuerCertificateChain(certChain []string) *SdJwtVcBuilder {
	b.issuerCertificateChain = &certChain
	return b
}

func (b *SdJwtVcBuilder) WithAllowNonHttpsIssuerUrl(allowNonHttps bool) *SdJwtVcBuilder {
	b.allowNonHttps = allowNonHttps
	return b
}

func (b *SdJwtVcBuilder) WithLifetime(lifetime int64) *SdJwtVcBuilder {
	b.lifetime = &lifetime
	return b
}

func (b *SdJwtVcBuilder) WithHaipCompatibility() *SdJwtVcBuilder {
	b.ensureHaipCompatible = true
	return b
}

func (b *SdJwtVcBuilder) WithIssuerUrl(url string) *SdJwtVcBuilder {
	b.issuerUrl = &url
	return b
}

func (b *SdJwtVcBuilder) WithSubject(sub string) *SdJwtVcBuilder {
	b.subject = &sub
	return b
}

func (b *SdJwtVcBuilder) WithStatus(status string) *SdJwtVcBuilder {
	b.status = &status
	return b
}

func (b *SdJwtVcBuilder) WithVerifiableCredentialType(vct string) *SdJwtVcBuilder {
	b.vct = &vct
	return b
}

func (b *SdJwtVcBuilder) WithHashingAlgorithm(alg HashingAlgorithm) *SdJwtVcBuilder {
	b.sdAlg = &alg
	return b
}

func (b *SdJwtVcBuilder) WithDisclosures(disclosures []DisclosureContent) *SdJwtVcBuilder {
	b.disclosures = disclosures
	return b
}

func (b *SdJwtVcBuilder) WithClock(clock Clock) *SdJwtVcBuilder {
	b.clock = &clock
	return b
}

func (b *SdJwtVcBuilder) WithHolderKey(key jwk.Key) *SdJwtVcBuilder {
	b.cnfPubKey = &CnfField{
		Jwk: key,
	}
	return b
}

func (b *SdJwtVcBuilder) Build(jwtCreator JwtCreator) (SdJwtVc, error) {
	payload := map[string]any{}
	if b.issuerUrl != nil {
		if !strings.HasPrefix(*b.issuerUrl, "https://") && !b.allowNonHttps {
			return "", fmt.Errorf("issuer url (iss) is required to be a valid https link when provided (but was '%s')", *b.issuerUrl)
		}
		payload[Key_Issuer] = *b.issuerUrl
	}
	if b.cnfPubKey != nil {
		payload[Key_Confirmationkey] = *b.cnfPubKey
	}

	if b.vct != nil {
		payload[Key_VerifiableCredentialType] = *b.vct
	} else {
		return "", fmt.Errorf("'%s' is required but was not supplied", Key_VerifiableCredentialType)
	}

	if b.subject != nil {
		payload[Key_Subject] = *b.subject
	}

	if b.clock != nil {
		now := (*b.clock).Now()
		payload[Key_IssuedAt] = now
		if b.lifetime != nil {
			payload[Key_ExpiryTime] = now + *b.lifetime
		}
	}

	disclosures, err := EncodeDisclosures(b.disclosures)
	if err != nil {
		return "", err
	}

	if len(b.disclosures) != 0 {
		if b.sdAlg == nil {
			return "", fmt.Errorf("no hashing algorithm defined while there are disclosures")
		}
		encoded, err := HashEncodedDisclosures(*b.sdAlg, disclosures)
		if err != nil {
			return "", err
		}
		payload[Key_Sd] = encoded
	}

	if b.sdAlg != nil {
		payload[Key_SdAlg] = *b.sdAlg
	}
	if b.status != nil {
		payload[Key_Status] = *b.status
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize payload: %v", err)
	}

	headers := map[string]any{
		"typ": SdJwtVcTyp,
	}

	if b.issuerCertificateChain != nil {
		headers["x5c"] = b.issuerCertificateChain
	}

	jwt, err := jwtCreator.CreateSignedJwt(headers, string(payloadJson))
	if err != nil {
		return "", fmt.Errorf("failed to create jwt: %v", err)
	}

	return CreateSdJwtVc(IssuerSignedJwt(jwt), disclosures), nil
}
