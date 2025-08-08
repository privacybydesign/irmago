package eudi

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

// ParsePemCertificateChainToX5cFormat takes in the raw contents of a PEM formatted certificate
// file and returns the contents of the chain in the format expected
// as the `x5c` header parameter of a jwt.
func ParsePemCertificateChainToX5cFormat(data []byte) ([]string, error) {
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
