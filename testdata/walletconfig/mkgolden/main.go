// Command mkgolden regenerates testdata/walletconfig/golden — a signed wallet
// config, the certificates that verify it, and a readable copy of its payload —
// and testdata/walletconfig/source, the curation directory `yivi eudi config
// build` compiles into that same payload.
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
		SchemaVersion:   walletconfig.CurrentSchemaVersion,
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
		// In entity-id order, which is how `config build` orders a curation directory.
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
		},
	}

	// In directory-name order, as `config build` orders a curation directory.
	config.CredentialCatalog = []walletconfig.CatalogEntry{
		{
			VCT:            "https://golden.example/vct/email",
			VCTMetadataURL: "https://golden.example/.well-known/vct/email",
			InStore:        true,
			Offerings: []walletconfig.Offering{{
				IssuanceURLs: map[string]string{
					"default": "https://issue.golden.example/email",
					"nl":      "https://issue.golden.example/nl/email",
				},
				IssuerMetadataURL: "https://issuer.golden.example",
			}},
		},
		{
			VCT:            "urn:eudi:pid:golden:1",
			VCTMetadataURL: "https://metadata.golden.example/vct/urn-eudi-pid-golden-1.json",
			Offerings: []walletconfig.Offering{
				{IssuanceURLs: map[string]string{"default": "https://pid.golden.example/start"}},
				{IssuanceURLs: map[string]string{"default": "https://pid-alt.golden.example/start"}, IssuerMetadataURL: "https://pid-alt.golden.example"},
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

	writeSource(filepath.Join("testdata", "walletconfig", "source"), issuerRoot, issuerCA, verifier)
}

// writeSource writes the curation directory that builds the golden payload: the
// worked example an operator copies, and the fixture the CLI tests compile.
func writeSource(dir string, issuerRoot, issuerCA, verifier *x509.Certificate) {
	entities := filepath.Join(dir, "entities")
	for _, sub := range []string{"golden-issuer-ca", "golden-verifier", "golden-party"} {
		if err := os.MkdirAll(filepath.Join(entities, sub), 0o755); err != nil {
			log.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	write("config.json", []byte(`{
  "id": "yivi-golden",
  "environment": "golden",
  "version": 1,
  "next_update_days": 30,
  "grace_period_days": 7,
  "minimum_app_build": 100,
  "policy": {
    "minimum_trust_level": { "issuance": "low", "disclosure": "medium" }
  }
}
`))
	write("entities/golden-issuer-ca/entity.json", []byte(`{
  "name": { "en": "Golden Issuers", "nl": "Gouden Uitgevers" },
  "roles": ["issuer"],
  "trust_level": "high",
  "handles": [
    {
      "type": "x509_ca",
      "root_certificate": "root.crt",
      "intermediates": ["issuing-ca.crt"],
      "crl_distribution_points": ["https://crl.golden.example/root.crl"]
    }
  ]
}
`))
	write("entities/golden-issuer-ca/root.crt", pemOf(issuerRoot))
	write("entities/golden-issuer-ca/issuing-ca.crt", pemOf(issuerCA))
	write("entities/golden-verifier/entity.json", []byte(`{
  "name": { "en": "Golden Verifier" },
  "roles": ["verifier"],
  "trust_level": "medium",
  "handles": [
    { "type": "x509_cert", "certificate": "verifier.crt" }
  ],
  "constraints": {
    "disclosure": {
      "allowed_queries": [
        { "credential": "https://golden.example/vct/email", "attributes": ["email"] }
      ]
    }
  }
}
`))
	write("entities/golden-verifier/verifier.crt", pemOf(verifier))
	write("entities/golden-party/entity.json", []byte(`{
  "name": { "en": "Golden Party", "nl": "Gouden Partij" },
  "roles": ["issuer", "verifier"],
  "trust_level": "high",
  "logo": { "url": "https://assets.golden.example/party.png", "file": "party.png" },
  "handles": [
    { "type": "did", "did": "did:web:party.golden.example" }
  ],
  "constraints": {
    "issuance": { "allowed_credentials": ["https://golden.example/vct/email"] }
  }
}
`))
	// The golden payload's logo digest is the SHA-256 of the empty string, so the
	// example's logo file is empty: `build` computes the digest from it.
	write("entities/golden-party/party.png", []byte{})

	for _, sub := range []string{"email", "pid"} {
		if err := os.MkdirAll(filepath.Join(dir, "credentials", sub), 0o755); err != nil {
			log.Fatal(err)
		}
	}
	write("credentials/email/credential.json", []byte(`{
  "vct": "https://golden.example/vct/email",
  "vct_metadata_url": "https://golden.example/.well-known/vct/email",
  "in_store": true,
  "offerings": [
    {
      "issuance_urls": {
        "default": "https://issue.golden.example/email",
        "nl": "https://issue.golden.example/nl/email"
      },
      "issuer_metadata_url": "https://issuer.golden.example"
    }
  ]
}
`))
	write("credentials/pid/credential.json", []byte(`{
  "vct": "urn:eudi:pid:golden:1",
  "vct_metadata_url": "https://metadata.golden.example/vct/urn-eudi-pid-golden-1.json",
  "offerings": [
    { "issuance_urls": { "default": "https://pid.golden.example/start" } },
    {
      "issuance_urls": { "default": "https://pid-alt.golden.example/start" },
      "issuer_metadata_url": "https://pid-alt.golden.example"
    }
  ]
}
`))
	fmt.Printf("wrote %s\n", dir)
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
