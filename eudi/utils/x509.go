package utils

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func ObtainIssuerUrlFromCertChain(certChain []*x509.Certificate) (string, error) {
	if len(certChain) == 0 {
		return "", fmt.Errorf("no certificate to get host name from")
	}
	leaf := certChain[0]
	if len(leaf.URIs) == 0 {
		return "", fmt.Errorf("no URIs in certificate")
	}
	for _, uri := range leaf.URIs {
		if uri != nil {
			return uri.String(), nil
		}
	}
	return "", fmt.Errorf("all URIs are nil")
}

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

func ConvertPemCertificateChainToX5cFormat(certs []*x509.Certificate) ([]string, error) {
	x5c := []string{}

	for _, cert := range certs {
		encoded := base64.StdEncoding.EncodeToString(cert.Raw)
		x5c = append(x5c, encoded)
	}

	return x5c, nil

}

// ParsePemCertificateChainToX5cFormat takes in the raw contents of a PEM formatted certificate
// file and returns the contents of the chain in the format expected
// as the `x5c` header parameter of a jwt.
func ParsePemCertificateChainToX5cFormat(data []byte) ([]string, error) {
	certs, err := ParsePemCertificateChain(data)
	if err != nil {
		return nil, err
	}
	return ConvertPemCertificateChainToX5cFormat(certs)
}

// CreateX509VerifyOptionsFromCertChain creates x509.VerifyOptions that can be added
// to the `VerificationContext` as the trusted certificate chain.
func CreateX509VerifyOptionsFromCertChain(pemChainData []byte) (*x509.VerifyOptions, error) {
	certs, err := ParsePemCertificateChain(pemChainData)
	if err != nil {
		return nil, err
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(certs[0])

	intermediatePool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediatePool.AddCert(cert)
	}

	certVerifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	return &certVerifyOpts, nil
}

func GetRevocationListsForIssuer(authorityKeyId []byte, issuer pkix.Name, revocationLists []*x509.RevocationList) []*x509.RevocationList {
	var clrs []*x509.RevocationList
	for _, rl := range revocationLists {
		if bytes.Equal(rl.AuthorityKeyId, authorityKeyId) && rl.Issuer.ToRDNSequence().String() == issuer.ToRDNSequence().String() {
			clrs = append(clrs, rl)
		}
	}
	return clrs
}

func VerifyCertificateAgainstIssuerRevocationLists(cert *x509.Certificate, revocationLists []*x509.RevocationList) error {
	issuerRevocationLists := GetRevocationListsForIssuer(cert.AuthorityKeyId, cert.Issuer, revocationLists)

	for _, revocationList := range issuerRevocationLists {
		for _, revokedCert := range revocationList.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate is revoked by issuer %v in revocation list with number %v", cert.Issuer.ToRDNSequence().String(), revocationList.Number)
			}
		}
	}
	return nil
}

// VerifyRevocationListsSignatures verifies the signatures of the revocation lists for a given parent certificate.
// In case of a revocation list for the root certificate, this will verify for the root certificate itself.
func VerifyRevocationListsSignatures(parentCert *x509.Certificate, revocationLists []*x509.RevocationList) error {
	parentRevocationLists := GetRevocationListsForIssuer(parentCert.SubjectKeyId, parentCert.Subject, revocationLists)
	for _, crl := range parentRevocationLists {
		if err := crl.CheckSignatureFrom(parentCert); err != nil {
			return err
		}
	}
	return nil
}
