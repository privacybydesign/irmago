// Command mkgolden regenerates testdata/walletconfig/golden: a signed wallet
// config, the certificates that verify it, and a readable copy of its payload.
//
//	go run ./testdata/walletconfig/mkgolden
//
// Keys are generated fresh and discarded; only the artifacts are committed. Every
// date is fixed so that eudi/walletconfig's golden tests can pin their clock
// rather than read the wall clock. Certificates live for decades for the same
// reason: the fixture must not rot.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
)

// Keep these in step with eudi/walletconfig/golden_test.go.
var (
	notBefore  = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	issuedAt   = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	nextUpdate = issuedAt.Add(30 * 24 * time.Hour)
)

func main() {
	out := filepath.Join("testdata", "walletconfig", "golden")
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}

	// The config CA: root, intermediate, signer.
	rootKey, root := ca("Yivi Golden Wallet Config Root CA", nil, nil, 30)
	intermediateKey, intermediate := ca("Yivi Golden Wallet Config CA", root, rootKey, 20)
	signerKey, signer := endEntity("yivi-golden-config-signer", intermediate, intermediateKey, 10, nil)

	// The parties the config vouches for.
	issuerRootKey, issuerRoot := ca("Golden Issuer Root CA", nil, nil, 30)
	issuerCAKey, issuerCA := ca("Golden Issuer CA", issuerRoot, issuerRootKey, 20)
	_, verifier := endEntity("verifier.golden.example", issuerCA, issuerCAKey, 10, func(t *x509.Certificate) {
		t.DNSNames = []string{"verifier.golden.example"}
	})

	config := &walletconfig.Config{
		SchemaVersion:   "1.0",
		ID:              "yivi-golden",
		Environment:     "golden",
		Version:         1,
		IssuedAt:        walletconfig.NewUnixTime(issuedAt),
		NextUpdate:      walletconfig.NewUnixTime(nextUpdate),
		GracePeriodSecs: 7 * 24 * 60 * 60,
		MinimumAppBuild: 100,
		Policy: walletconfig.Policy{MinimumTrustLevel: walletconfig.MinimumTrustLevel{
			Issuance:   clientmodels.TrustLevel_Low,
			Disclosure: clientmodels.TrustLevel_Medium,
		}},
		TrustedEntities: []walletconfig.TrustedEntity{
			{
				ID:         "golden-issuer-ca",
				Name:       clientmodels.TranslatedString{"en": "Golden Issuers", "nl": "Gouden Uitgevers"},
				Roles:      []walletconfig.Role{walletconfig.RoleIssuer},
				TrustLevel: clientmodels.TrustLevel_High,
				Handles: []walletconfig.Handle{{
					Type:                  walletconfig.HandleTypeX509CA,
					RootCertificate:       &walletconfig.Certificate{Certificate: issuerRoot},
					Intermediates:         []walletconfig.Certificate{{Certificate: issuerCA}},
					CRLDistributionPoints: []string{"https://crl.golden.example/root.crl"},
				}},
			},
			{
				ID:         "golden-verifier",
				Name:       clientmodels.TranslatedString{"en": "Golden Verifier"},
				Roles:      []walletconfig.Role{walletconfig.RoleVerifier},
				TrustLevel: clientmodels.TrustLevel_Medium,
				Handles: []walletconfig.Handle{{
					Type:        walletconfig.HandleTypeX509Cert,
					Certificate: &walletconfig.Certificate{Certificate: verifier},
				}},
				Constraints: &walletconfig.Constraints{
					Disclosure: &walletconfig.DisclosureConstraint{AllowedQueries: []walletconfig.AllowedQuery{
						{Credential: "https://golden.example/vct/email", Attributes: []string{"email"}},
					}},
				},
			},
			{
				ID:         "golden-party",
				Name:       clientmodels.TranslatedString{"en": "Golden Party", "nl": "Gouden Partij"},
				Logo:       &walletconfig.Logo{URL: "https://assets.golden.example/party.png", Digest: "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
				Roles:      []walletconfig.Role{walletconfig.RoleIssuer, walletconfig.RoleVerifier},
				TrustLevel: clientmodels.TrustLevel_High,
				Handles: []walletconfig.Handle{{
					Type: walletconfig.HandleTypeDID,
					DID:  "did:web:party.golden.example",
				}},
				Constraints: &walletconfig.Constraints{
					Issuance: &walletconfig.IssuanceConstraint{AllowedCredentials: []string{"https://golden.example/vct/email"}},
				},
			},
		},
	}

	signed, err := walletconfig.Sign(config, signerKey, []*x509.Certificate{signer, intermediate})
	if err != nil {
		log.Fatal(err)
	}
	readable, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	write("config.jws", signed)
	write("config.json", append(readable, '\n'))
	write("root.crt", pemOf(root))
	write("intermediate.crt", pemOf(intermediate))
	write("signer.crt", pemOf(signer))
	fmt.Printf("wrote %s\n", out)
}

func ca(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, years int) (*ecdsa.PrivateKey, *x509.Certificate) {
	key := newKey()
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi"}, Country: []string{"NL"}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          randomBytes(20),
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	return key, issue(template, parent, key.Public(), parentKey)
}

func endEntity(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, years int, mutate func(*x509.Certificate)) (*ecdsa.PrivateKey, *x509.Certificate) {
	key := newKey()
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi"}, Country: []string{"NL"}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          randomBytes(20),
	}
	if mutate != nil {
		mutate(template)
	}
	return key, issue(template, parent, key.Public(), parentKey)
}

func issue(template, parent *x509.Certificate, publicKey any, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return certificate
}

func newKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func serial() *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func pemOf(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}
