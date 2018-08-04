package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign path_to_private_key path_to_irma_configuration",
	Short: "Sign a scheme manager directory",
	Long:  "Sign a scheme manager directory, using the specified ECDSA key. Outputs an index file, signature over the index file, and the public key in the specified directory.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		signManager(args)
	},
}

func init() {
	RootCmd.AddCommand(signCmd)
}

func signManager(args []string) {
	// Validate arguments
	privatekey, err := readPrivateKey(args[0])
	if err != nil {
		die("Failed to read private key:", err)
	}
	confpath, err := filepath.Abs(args[1])
	if err != nil {
		die("Invalid path", err)
	}
	if err = fs.AssertPathExists(confpath); err != nil {
		die("Specified path does not exist", nil)
	}

	// Write timestamp
	bts := []byte(strconv.FormatInt(time.Now().Unix(), 10) + "\n")
	if err = ioutil.WriteFile(confpath+"/timestamp", bts, 0644); err != nil {
		die("Failed to write timestamp", err)
	}

	// Traverse dir and add file hashes to index
	var index irma.SchemeManagerIndex = make(map[string]irma.ConfigurationFileHash)
	err = filepath.Walk(confpath, func(path string, info os.FileInfo, err error) error {
		return calculateFileHash(path, info, err, confpath, index)
	})
	if err != nil {
		die("Failed to calculate file index:", err)
	}

	// Write index
	bts = []byte(index.String())
	if err = ioutil.WriteFile(confpath+"/index", bts, 0644); err != nil {
		die("Failed to write index", err)
	}

	// Create and write signature
	indexHash := sha256.Sum256(bts)
	r, s, err := ecdsa.Sign(rand.Reader, privatekey, indexHash[:])
	if err != nil {
		die("Failed to sign index:", err)
	}
	sigbytes, err := asn1.Marshal([]*big.Int{r, s})
	if err != nil {
		die("Failed to serialize signature:", err)
	}
	if err = ioutil.WriteFile(confpath+"/index.sig", sigbytes, 0644); err != nil {
		die("Failed to write index.sig", err)
	}

	// Write public key
	bts, err = x509.MarshalPKIXPublicKey(&privatekey.PublicKey)
	if err != nil {
		die("Failed to serialize public key", err)
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bts})
	ioutil.WriteFile(confpath+"/pk.pem", pemEncodedPub, 0644)
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
		strings.Contains(path, "/.git/") || // No need to traverse .git dirs, can take quite long
		strings.Contains(path, "/PrivateKeys/") { // Don't sign private keys
		return nil
	}
	// Skip everything except the stuff we do want
	if !strings.HasSuffix(path, ".xml") &&
		!strings.HasSuffix(path, ".png") &&
		!regexp.MustCompile("kss-\\d+\\.pem$").Match([]byte(filepath.Base(path))) &&
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
	index[relativePath] = hash[:]
	return nil
}

func die(message string, err error) {
	if err != nil {
		fmt.Println(message, err)
	} else {
		fmt.Println(message)
	}
	os.Exit(1)
}
