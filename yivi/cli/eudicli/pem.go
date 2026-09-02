package eudicli

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/privacybydesign/irmago/eudi/utils"
	"golang.org/x/term"
)

// readCertificateChain reads the certificates in a PEM file, in file order, or
// a single DER certificate.
func readCertificateChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	chain, err := utils.ParsePemCertificateChain(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if len(chain) == 0 {
		// No PEM at all: try raw DER.
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s holds neither PEM nor DER certificates", path)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// readCertificate reads exactly one certificate from a PEM or DER file.
func readCertificate(path string) (*x509.Certificate, error) {
	chain, err := readCertificateChain(path)
	if err != nil {
		return nil, err
	}
	if len(chain) != 1 {
		return nil, fmt.Errorf("%s holds %d certificates, expected one", path, len(chain))
	}
	return chain[0], nil
}

// readSigningKey reads a PEM private key, prompting for a passphrase when the PEM
// is encrypted.
//
// RFC 1423 PEM encryption (what `openssl ec -aes256` writes) is supported because
// operators have such files, but its key derivation is one round of MD5 and Go has
// deprecated it. A stopgap for a key that can vouch for any party at the top rung:
// the intended end state is a key that never leaves hardware, which is why `sign`
// is a separate command from `build` and takes a crypto.Signer.
func readSigningKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}

	der := block.Bytes
	//nolint:staticcheck // RFC 1423 is deprecated; see the doc comment.
	if x509.IsEncryptedPEMBlock(block) {
		Logger.Warn("the signing key uses RFC 1423 PEM encryption, whose key derivation is one round of MD5")
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // as above
		der, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", path, err)
		}
	}

	return parsePrivateKey(der, path)
}

func parsePrivateKey(der []byte, path string) (crypto.Signer, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s holds a %T, which cannot sign", path, parsed)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%s holds no EC, PKCS#8 or PKCS#1 private key", path)
}

// writePEM writes one PEM block to path with the given mode.
func writePEM(path string, block *pem.Block, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(block), mode)
}
