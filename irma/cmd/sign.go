package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign [<privatekey>] [<path>]",
	Short: "Sign a scheme directory",
	Long: `Sign a scheme directory, using the specified ECDSA key. Both arguments are optional; "sk.pem" and the working directory are the defaults. Outputs an index file, signature over the index file, and the public key in the specified directory.

Careful: this command could fail and invalidate or destroy your scheme directory! Use this only if you can restore it from git or backups.`,
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

		if err = common.AssertPathExists(confpath); err != nil {
			return err
		}

		skipverification, err := cmd.Flags().GetBool("noverification")
		if err != nil {
			return err
		}
		if err := signScheme(privatekey, confpath, skipverification); err != nil {
			die("Failed to sign scheme", err)
		}
		return nil
	},
}

func init() {
	schemeCmd.AddCommand(signCmd)

	signCmd.Flags().BoolP("noverification", "n", false, "Skip verification of the scheme after signing it")
}

func signScheme(privatekey *ecdsa.PrivateKey, path string, skipverification bool) error {
	filename, err := common.SchemeFilename(path)
	if err != nil {
		return err
	}
	bts, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return err
	}
	id, typ, err := common.SchemeInfo(filename, bts)
	if err != nil {
		return err
	}

	// Write timestamp
	bts = []byte(strconv.FormatInt(time.Now().Unix(), 10) + "\n")
	if err := ioutil.WriteFile(filepath.Join(path, "timestamp"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write timestamp", 0)
	}

	// Traverse dir and add file hashes to index
	var index irma.SchemeManagerIndex = make(map[string]irma.SchemeFileHash)
	err = common.WalkDir(path, func(p string, info os.FileInfo) error {
		return calculateFileHash(id, path, p, info, index, irma.SchemeType(typ))
	})
	if err != nil {
		return errors.WrapPrefix(err, "Failed to calculate file index", 0)
	}

	// Write index
	bts = []byte(index.String())
	if err := ioutil.WriteFile(filepath.Join(path, "index"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write index", 0)
	}

	// Create and write signature
	sigbytes, err := signed.Sign(privatekey, bts)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to serialize signature:", 0)
	}
	if err = ioutil.WriteFile(filepath.Join(path, "index.sig"), sigbytes, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write index.sig", 0)
	}

	// Write public key
	pemEncodedPub, err := signed.MarshalPemPublicKey(&privatekey.PublicKey)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to serialize public key", 0)
	}
	if err := ioutil.WriteFile(filepath.Join(path, "pk.pem"), pemEncodedPub, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write public key", 0)
	}

	if skipverification {
		return nil
	}

	// Verify that our folder is a valid scheme
	if err := VerifyScheme(path, false); err != nil {
		die("Scheme was signed but verification failed", err)
	}
	return nil
}

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	bts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return signed.UnmarshalPemPrivateKey(bts)
}

func calculateFileHash(id, confpath, path string, info os.FileInfo, index irma.SchemeManagerIndex, typ irma.SchemeType) error {
	if skipSigning(path, info, typ) {
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
	relativePath = filepath.Join(id, relativePath)

	if filepath.Ext(path) != ".png" && bytes.Contains(bts, []byte("\r\n")) {
		return errors.Errorf("%s contains CRLF (Windows) line endings, please convert to LF", relativePath)
	}

	hash := sha256.Sum256(bts)
	index[filepath.ToSlash(relativePath)] = hash[:]
	return nil
}

func skipSigning(path string, info os.FileInfo, typ irma.SchemeType) bool {
	// Skip stuff we don't want
	if info.IsDir() || // Can only sign files
		strings.HasSuffix(path, "index") || // Skip the index file itself
		strings.Contains(filepath.ToSlash(path), "/.git/") { // No need to traverse .git dirs, can take quite long
		return true
	}

	switch typ {
	case irma.SchemeTypeIssuer:
		if strings.Contains(filepath.ToSlash(path), "/PrivateKeys/") || // Don't sign private keys
			strings.Contains(filepath.ToSlash(path), "/Proofs/") { // Or key proofs
			return true
		}
		if !strings.HasSuffix(path, ".xml") &&
			!strings.HasSuffix(path, ".png") &&
			!regexp.MustCompile("kss-\\d+\\.pem$").Match([]byte(filepath.Base(path))) &&
			filepath.Base(path) != "timestamp" {
			return true
		}
	case irma.SchemeTypeRequestor:
		if !strings.HasSuffix(path, ".json") &&
			filepath.Base(path) != "timestamp" {
			return true
		}
	}
	return false
}
