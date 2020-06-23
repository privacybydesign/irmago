package common

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger

// Disables HTTP forcing in irma.HTTPTransport for all instances,
// regardless of the instance's ForceHTTPS member.
// Only for use in unit tests.
var ForceHTTPS = true

const (
	sessionChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	sessionTokenLength = 20
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
		return errors.New("path exists but is not a directory")
	}
	return nil
}

// Save the filecontents at the specified path atomically:
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
	err = ioutil.WriteFile(filepath.Join(dir, tempfilename), content, 0600)
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
		subpath := path[len(src):]
		if info.IsDir() {
			if err := EnsureDirectoryExists(dest + subpath); err != nil {
				return err
			}
		} else {
			srcfile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { e = srcfile.Close() }()
			bts, err := ioutil.ReadAll(srcfile)
			if err != nil {
				return err
			}
			if err := SaveFile(dest+subpath, bts); err != nil {
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
		bts, err = ioutil.ReadFile(path)
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

// iterateSubfolders iterates over the subfolders of the specified path,
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

// walkDir recursively walks the file tree rooted at path, following symlinks (unlike filepath.Walk).
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
	r := make([]byte, sessionTokenLength)
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}

	b := make([]byte, sessionTokenLength)
	for i := range b {
		b[i] = sessionChars[r[i]%byte(len(sessionChars))]
	}
	return string(b)
}
