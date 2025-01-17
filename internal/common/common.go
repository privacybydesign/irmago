package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var Logger *logrus.Logger

// ForceHTTPS disables HTTP forcing in irma.HTTPTransport for all instances,
// regardless of the instance's ForceHTTPS member.
// Only for use in unit tests.
var ForceHTTPS = true

const (
	AlphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	NumericChars      = "0123456789"

	sessionTokenLength = 20 // duplicated in SessionTokenRegex as strconv.Itoa cannot be used in const block
	pairingCodeLength  = 4

	SessionTokenRegex = "[" + AlphanumericChars + "]{20}"

	EncryptedSchemePrivateKeyHeader = "ENCRYPTED IRMA SCHEME PRIVATE KEY"
)

// AssertPathExists returns nil only if it has been successfully
// verified that all specified paths exists.
func AssertPathExists(paths ...string) error {
	for _, p := range paths {
		exist, err := PathExists(p)
		if err != nil {
			return err
		}
		if !exist {
			return errors.Errorf("Path %s does not exist", p)
		}
	}
	return nil
}

func AssertPathNotExists(paths ...string) error {
	for _, p := range paths {
		exist, err := PathExists(p)
		if err != nil {
			return err
		}
		if exist {
			return errors.Errorf("Path %s exists but should not", p)
		}
	}
	return nil
}

// PathExists checks if the specified path exists.
func PathExists(path string) (bool, error) {
	_, exists, err := Stat(path)
	return exists, err
}

func Stat(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		return info, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func EnsureDirectoryExists(path string) error {
	info, exists, err := Stat(path)
	if err != nil {
		return err
	}
	if !exists {
		return os.MkdirAll(path, 0700)
	}
	if !info.IsDir() {
		return errors.Errorf("path %s exists but is not a directory", path)
	}
	return nil
}

// SaveFile saves the file contents at the specified path atomically:
// - first save the content in a temp file with a random filename in the same dir
// - then rename the temp file to the specified filepath, overwriting the old file
func SaveFile(fpath string, content []byte) (err error) {
	fpath = filepath.FromSlash(fpath)
	Logger.Debug("writing ", fpath)
	info, exists, err := Stat(fpath)
	if err != nil {
		return err
	}
	if exists && (info.IsDir() || !info.Mode().IsRegular()) {
		return errors.New("invalid destination path: not a file")
	}

	// Only accept 'simple' paths without . or .. or multiple separators
	if fpath != filepath.Clean(fpath) {
		return errors.New("invalid destination path")
	}

	// Read random data for filename and convert to hex
	randBytes := make([]byte, 16)
	_, err = rand.Read(randBytes)
	if err != nil {
		return
	}
	tempfilename := hex.EncodeToString(randBytes)

	// Create temp file
	dir := path.Dir(fpath)
	err = os.WriteFile(filepath.Join(dir, tempfilename), content, 0600)
	if err != nil {
		return
	}

	// Rename, overwriting old file
	return os.Rename(filepath.Join(dir, tempfilename), fpath)
}

func CopyDirectory(src, dest string) error {
	if err := EnsureDirectoryExists(dest); err != nil {
		return err
	}

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) (e error) {
		if err != nil {
			return err
		}
		if path == src {
			return
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dest, relPath)
		if info.IsDir() {
			if err := EnsureDirectoryExists(destPath); err != nil {
				return err
			}
		} else {
			srcfile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { e = srcfile.Close() }()
			bts, err := io.ReadAll(srcfile)
			if err != nil {
				return err
			}
			if err := SaveFile(destPath, bts); err != nil {
				return err
			}
		}
		return
	})

}

// ReadKey returns either the content of the file specified at path, if it exists,
// or []byte(key) otherwise. It is an error to specify both or none arguments, or
// specify an empty or unreadable file. If there is no error then the return []byte is non-empty.
func ReadKey(key, path string) ([]byte, error) {
	if (key != "" && path != "") || (key == "" && path == "") {
		return nil, errors.New("provide either key or path to key")
	}

	var bts []byte

	if path == "" {
		bts = []byte(key)
	} else {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, errors.WrapPrefix(err, "failed to stat key", 0)
		}
		if stat.IsDir() {
			return nil, errors.New("cannot read key from a directory")
		}
		if !stat.Mode().IsRegular() {
			return nil, errors.New("cannot read key from nonregular file")
		}
		bts, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}

	if len(bts) == 0 {
		return nil, errors.New("empty key provided")
	}
	return bts, nil
}

// Base64Decode decodes the specified bytes as any of the Base64 dialects:
// standard encoding (+, /) and URL encoding (-, _), with or without padding.
func Base64Decode(b []byte) ([]byte, error) {
	var (
		err       error
		bts       []byte
		encodings = []*base64.Encoding{base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding, base64.StdEncoding}
	)
	for _, encoding := range encodings {
		if bts, err = encoding.DecodeString(string(b)); err == nil {
			break
		}
	}
	return bts, err
}

// IterateSubfolders iterates over the subfolders of the specified path,
// calling the specified handler each time. If anything goes wrong, or
// if the caller returns a non-nil error, an error is immediately returned.
func IterateSubfolders(path string, handler func(string, os.FileInfo) error) error {
	return iterateFiles(path, true, handler)
}

func iterateFiles(path string, onlyDirs bool, handler func(string, os.FileInfo) error) error {
	files, err := filepath.Glob(filepath.Join(path, "*"))
	if err != nil {
		return err
	}

	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			return err
		}
		if onlyDirs && !stat.IsDir() {
			continue
		}
		if filepath.Base(file) == ".git" {
			continue
		}
		err = handler(file, stat)
		if err != nil {
			return err
		}
	}

	return nil
}

// WalkDir recursively walks the file tree rooted at path, following symlinks (unlike filepath.Walk).
// Avoiding loops is the responsibility of the caller.
func WalkDir(path string, handler func(string, os.FileInfo) error) error {
	return iterateFiles(path, false, func(p string, info os.FileInfo) error {
		if info.IsDir() {
			if err := handler(p, info); err != nil {
				return err
			}
			return WalkDir(p, handler)
		}
		return handler(p, info)
	})
}

func RandomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}
	return res
}

type SSECtx struct {
	Component, Arg string
}

func NewSessionToken() string {
	return NewRandomString(sessionTokenLength, AlphanumericChars)
}

func NewPairingCode() string {
	return NewRandomString(pairingCodeLength, NumericChars)
}

func NewRandomString(count int, characterSet string) string {
	// We read bytes (0-255) from the secure random number generator.
	// If the character set length is smaller than and not a divider of 256, we should only consider the random numbers
	// smaller than the character set length minus the remainder after division. This ensures an even distribution.
	byteValueUpperbound := uint8(256 - (256 % len(characterSet)))

	// We collect 16 bytes of randomness at once for efficiency.
	randomnessBuffer := make([]byte, 16)

	b := make([]byte, count)
	i := 0
	for bufferIndex := 0; i < len(b); bufferIndex = (bufferIndex + 1) % len(randomnessBuffer) {
		if bufferIndex == 0 {
			_, err := rand.Read(randomnessBuffer)
			if err != nil {
				panic(err)
			}
		}
		byteValue := randomnessBuffer[bufferIndex]
		if byteValueUpperbound == 0 || byteValue < byteValueUpperbound {
			if len(characterSet) < 256 {
				byteValue = byteValue % byte(len(characterSet))
			}
			b[i] = characterSet[byteValue]
			i++
		}
	}
	return string(b)
}

func IsIrmaconfDir(dir string) (bool, error) {
	if ok, err := containsSchemes(dir); err != nil || !ok {
		return false, err
	}
	return true, nil
}

func IsScheme(dir string, expectSignature bool) (bool, error) {
	filenames := []string{"description.xml", "description.json"}

filenameloop:
	for _, filename := range filenames {
		files := []string{filename}
		if expectSignature {
			files = append(files, "timestamp", "index", "index.sig")
		}
		for _, file := range files {
			exists, err := PathExists(filepath.Join(dir, file))
			if err != nil {
				return false, err
			}
			if !exists {
				continue filenameloop
			}
		}
		return true, nil
	}

	return false, nil
}

func ValidateSchemeID(id string) error {
	// We use the format 'schemeManager.issuer.credential.attribute' in full identifiers,
	// so dots can never be in a valid scheme id.
	if strings.Contains(id, ".") {
		return errors.New("scheme id contains a dot")
	}
	if IsTempSchemeDir(id) {
		return errors.New("scheme id uses forbidden prefix")
	}
	return nil
}

func IsTempSchemeDir(dirname string) bool {
	if strings.HasPrefix(dirname, ".tempscheme") || strings.HasPrefix(dirname, ".oldscheme") {
		return true
	}
	// In irmago version 0.11.0 and below, temporary directories were not marked as hidden yet. So, there
	// might be directories starting with 'tempscheme' or 'oldscheme' that should not be considered as a scheme.
	// To prevent directory name clashes, we forbid scheme IDs starting with these prefixes.
	if strings.HasPrefix(dirname, "tempscheme") || strings.HasPrefix(dirname, "oldscheme") {
		return true
	}
	return false
}

func containsSchemes(dir string) (bool, error) {
	var (
		hasSubdirs     bool
		hasOnlySchemes = true
	)
	err := IterateSubfolders(dir, func(d string, info os.FileInfo) error {
		if !hasOnlySchemes {
			return nil
		}
		hasSubdirs = true
		s, err := IsScheme(d, true)
		if err != nil {
			return err
		}
		hasOnlySchemes = s
		return nil
	})

	if !hasSubdirs || !hasOnlySchemes {
		return false, nil
	}
	return err == nil, err
}

func SchemeInfo(filename string, bts []byte) (string, string, error) {
	temp := struct {
		Type string `json:"schemetype" xml:"SchemeType"`
		ID   string `json:"id" xml:"Id"`
	}{}
	if err := Unmarshal(filename, bts, &temp); err != nil {
		return "", "", err
	}
	if temp.Type == "" {
		temp.Type = "issuer"
	}

	if temp.Type != "issuer" && temp.Type != "requestor" {
		return "", "", errors.New("unsupported scheme type")
	}
	if err := ValidateSchemeID(temp.ID); err != nil {
		return "", "", errors.WrapPrefix(err, fmt.Sprintf("invalid scheme id %s", temp.ID), 0)
	}
	return temp.ID, temp.Type, nil
}

func Unmarshal(filename string, bts []byte, dest interface{}) error {
	switch filepath.Ext(filename) {
	case ".xml":
		return xml.Unmarshal(bts, dest)
	case ".json":
		return json.Unmarshal(bts, dest)
	default:
		return errors.New("unsupported file format")
	}
}

func SchemeFilename(dir string) (string, error) {
	for _, filename := range SchemeFilenames {
		exists, err := PathExists(filepath.Join(dir, filename))
		if err != nil {
			return "", err
		}
		if exists {
			return filename, nil
		}
	}
	return "", errors.Errorf("no scheme file found in directory %s", dir)
}

var SchemeFilenames = []string{"description.xml", "description.json"}

// Close is a helper for absorbing errors in the `defer x.Close()` pattern
func Close(o io.Closer) {
	_ = o.Close()
}

func ParseLDContext(bts []byte) (string, error) {
	var v struct {
		LDContext string `json:"@context"`
	}
	if err := json.Unmarshal(bts, &v); err != nil {
		return "", err
	}
	return v.LDContext, nil
}

func ParseNestedLDContext(bts []byte) (string, error) {
	var v struct {
		Request struct {
			LDContext string `json:"@context"`
		} `json:"request"`
	}
	if err := json.Unmarshal(bts, &v); err != nil {
		return "", err
	}
	return v.Request.LDContext, nil
}

func ParseSchemePrivateKeyWithPassphrase(bts []byte, passphrase []byte) (*ecdsa.PrivateKey, error) {
	// Mask our custom private key header such that the SSH library understands it.
	sshBts := bytes.Replace(bts, []byte(EncryptedSchemePrivateKeyHeader), []byte("OPENSSH PRIVATE KEY"), 2)
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(sshBts, passphrase)
	if err != nil {
		return nil, err
	}
	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		return ecdsaKey, nil
	}
	return nil, errors.New("not an ECDSA key")
}

func MarshalSchemePrivateKeyWithPassphrase(key *ecdsa.PrivateKey, passphrase []byte) ([]byte, error) {
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", passphrase)
	if err != nil {
		return nil, err
	}
	pemBlock.Type = EncryptedSchemePrivateKeyHeader
	return pem.EncodeToMemory(pemBlock), nil
}
