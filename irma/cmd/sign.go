package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign [privatekey] [path]",
	Short: "Sign a scheme directory",
	Long: `Sign a scheme manager directory, using the specified ECDSA key. Both arguments are optional; "sk.pem" and the working directory are the defaults. Outputs an index file, signature over the index file, and the public key in the specified directory.

Careful: this command could fail and invalidate or destroy your scheme manager directory! Use this only if you can restore it from git or backups.`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate arguments
		var err error
		var sk, confpath string
		switch len(args) {
		case 0:
			sk = "sk.pem"
			confpath, err = os.Getwd()
		case 1:
			sk = args[0]
			confpath, err = os.Getwd()
		case 2:
			sk = args[0]
			confpath, err = filepath.Abs(args[1])
		}
		if err != nil {
			return errors.WrapPrefix(err, "Invalid path", 0)
		}

		privatekey, err := readPrivateKey(sk)
		if err != nil {
			return errors.WrapPrefix(err, "Failed to read private key:", 0)
		}

		if err = fs.AssertPathExists(confpath); err != nil {
			return err
		}

		skipverification, err := cmd.Flags().GetBool("noverification")
		if err != nil {
			return err
		}
		if err := signManager(privatekey, confpath, skipverification); err != nil {
			die("Failed to sign scheme", err)
		}
		return nil
	},
}

func init() {
	schemeCmd.AddCommand(signCmd)

	signCmd.Flags().BoolP("noverification", "n", false, "Skip verification of the scheme after signing it")
}

func signManager(privatekey *ecdsa.PrivateKey, confpath string, skipverification bool) error {
	// Write timestamp
	bts := []byte(strconv.FormatInt(time.Now().Unix(), 10) + "\n")
	if err := ioutil.WriteFile(filepath.Join(confpath, "timestamp"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write timestamp", 0)
	}

	// Traverse dir and add file hashes to index
	var index irma.SchemeManagerIndex = make(map[string]irma.ConfigurationFileHash)
	err := filepath.Walk(confpath, func(path string, info os.FileInfo, err error) error {
		return calculateFileHash(path, info, err, confpath, index)
	})
	if err != nil {
		return errors.WrapPrefix(err, "Failed to calculate file index:", 0)
	}

	// Write index
	bts = []byte(index.String())
	if err := ioutil.WriteFile(filepath.Join(confpath, "index"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write index", 0)
	}

	// Create and write signature
	indexHash := sha256.Sum256(bts)
	r, s, err := ecdsa.Sign(rand.Reader, privatekey, indexHash[:])
	if err != nil {
		return errors.WrapPrefix(err, "Failed to sign index:", 0)
	}
	sigbytes, err := asn1.Marshal([]*big.Int{r, s})
	if err != nil {
		return errors.WrapPrefix(err, "Failed to serialize signature:", 0)
	}
	if err = ioutil.WriteFile(filepath.Join(confpath, "index.sig"), sigbytes, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write index.sig", 0)
	}

	// Write public key
	bts, err = x509.MarshalPKIXPublicKey(&privatekey.PublicKey)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to serialize public key", 0)
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bts})
	if err := ioutil.WriteFile(filepath.Join(confpath, "pk.pem"), pemEncodedPub, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write public key", 0)
	}

	if skipverification {
		return nil
	}

	// Verify that our folder is a valid scheme
	if err := RunVerify(confpath, false); err != nil {
		die("Scheme was signed but verification failed", err)
	}
	return nil
}

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	bts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bts)
	return x509.ParseECPrivateKey(block.Bytes)
}

func calculateFileHash(path string, info os.FileInfo, err error, confpath string, index irma.SchemeManagerIndex) error {
	if err != nil {
		return err
	}
	// Skip stuff we don't want
	if info.IsDir() || // Can only sign files
		strings.HasSuffix(path, "index") || // Skip the index file itself
		strings.Contains(filepath.ToSlash(path), "/.git/") || // No need to traverse .git dirs, can take quite long
		strings.Contains(filepath.ToSlash(path), "/PrivateKeys/") { // Don't sign private keys
		return nil
	}
	// Skip everything except the stuff we do want
	if !strings.HasSuffix(path, ".xml") &&
		!strings.HasSuffix(path, ".png") &&
		!regexp.MustCompile("kss-\\d+\\.pem$").Match([]byte(filepath.ToSlash(filepath.Base(path)))) &&
		filepath.Base(path) != "timestamp" {
		return nil
	}

	bts, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	relativePath, err := filepath.Rel(confpath, path)
	if err != nil {
		return err
	}
	relativePath = filepath.Join(filepath.Base(confpath), relativePath)

	hash := sha256.Sum256(bts)
	index[filepath.ToSlash(relativePath)] = hash[:]
	return nil
}
