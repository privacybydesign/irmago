package irma

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"

	"github.com/go-errors/errors"
)

var DefaultSchemes = [2]SchemePointer{
	{
		URL: "https://schemes.yivi.app/irma-demo",
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHVnmAY+kGkFZn7XXozdI4HY8GOjm
54ngh4chTfn6WsTCf2w5rprfIqML61z2VTE4k8yJ0Z1QbyW6cdaao8obTQ==
-----END PUBLIC KEY-----`),
	},
	{
		URL: "https://schemes.yivi.app/pbdf",
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELzHV5ipBimWpuZIDaQQd+KmNpNop
dpBeCqpDwf+Grrw9ReODb6nwlsPJ/c/gqLnc+Y3sKOAJ2bFGI+jHBSsglg==
-----END PUBLIC KEY-----`),
	},
}

type (
	// SchemePointer points to a remote IRMA scheme, containing information to download the scheme,
	// including its (pinned) public key.
	SchemePointer struct {
		URL       string // URL to download scheme from
		Type      SchemeType
		Publickey []byte // Public key of scheme against which to verify files after they have been downloaded
	}

	Scheme interface {
		id() string
		idx() SchemeManagerIndex
		setIdx(idx SchemeManagerIndex)
		url() string
		timestamp() Timestamp
		setTimestamp(t Timestamp)
		setStatus(status SchemeManagerStatus)
		path() string
		setPath(path string)
		parseContents(conf *Configuration) error
		validate(conf *Configuration) (SchemeManagerStatus, error)
		update() error
		handleUpdateFile(conf *Configuration, path, filename string, bts []byte, transport *HTTPTransport, _ *IrmaIdentifierSet) error
		delete(conf *Configuration) error
		add(conf *Configuration)
		addError(conf *Configuration, err error)
		deleteError(conf *Configuration, err error)
		present(id string, conf *Configuration) bool
		typ() SchemeType
		purge(conf *Configuration)
	}

	// SchemeFileHash encodes the SHA256 hash of an authenticated
	// file under a scheme within the configuration folder.
	SchemeFileHash []byte

	// SchemeManagerIndex is a (signed) list of files under a scheme
	// along with their SHA266 hash
	SchemeManagerIndex map[string]SchemeFileHash

	SchemeManagerStatus string

	SchemeManagerError struct {
		Scheme string
		Status SchemeManagerStatus
		Err    error
	}

	SchemeType string
)

type DependencyChain []CredentialTypeIdentifier

const (
	SchemeManagerStatusValid               = SchemeManagerStatus("Valid")
	SchemeManagerStatusUnprocessed         = SchemeManagerStatus("Unprocessed")
	SchemeManagerStatusInvalidIndex        = SchemeManagerStatus("InvalidIndex")
	SchemeManagerStatusInvalidSignature    = SchemeManagerStatus("InvalidSignature")
	SchemeManagerStatusParsingError        = SchemeManagerStatus("ParsingError")
	SchemeManagerStatusContentParsingError = SchemeManagerStatus("ContentParsingError")

	SchemeTypeIssuer    = SchemeType("issuer")
	SchemeTypeRequestor = SchemeType("requestor")

	maxDepComplexity = 25
)

// DownloadDefaultSchemes downloads and adds the default schemes to this Configuration.
// When an error occurs, this function will revert its changes.
// Limitation: when this function is stopped unexpectedly (i.e. a panic or a sigint takes place),
// the scheme directory might get in an inconsistent state.
func (conf *Configuration) DownloadDefaultSchemes() error {
	Logger.Info("downloading default schemes (may take a while)")
	for _, s := range DefaultSchemes {
		Logger.WithFields(logrus.Fields{"url": s.URL}).Debugf("Downloading scheme")
		if err := conf.installScheme(s.URL, s.Publickey, ""); err != nil {
			return err
		}
	}
	Logger.Info("Finished downloading schemes")
	return nil
}

// InstallScheme downloads and adds the specified scheme to this Configuration,
// provided its signature is valid against the specified key.
// When an error occurs, this function will revert its changes.
// Limitation: when this function is stopped unexpectedly (i.e. a panic or a sigint takes place),
// the scheme directory might get in an inconsistent state.
func (conf *Configuration) InstallScheme(url string, publickey []byte) error {
	if len(publickey) == 0 {
		return errors.New("no public key specified")
	}
	return conf.installScheme(url, publickey, "")
}

// DangerousTOFUInstallScheme downloads and adds the specified scheme to this Configuration,
// downloading and trusting its public key from the scheme's remote URL.
// Limitation: when this function is stopped unexpectedly (i.e. a panic or a sigint takes place),
// the scheme directory might get in an inconsistent state.
func (conf *Configuration) DangerousTOFUInstallScheme(url string) error {
	return conf.installScheme(url, nil, "")
}

func (conf *Configuration) AutoUpdateSchemes(interval int) error {
	Logger.Infof("Updating schemes every %d minutes", interval)
	update := func() {
		if err := conf.UpdateSchemes(); err != nil {
			Logger.Error("Scheme autoupdater failed: ")
			if e, ok := err.(*errors.Error); ok {
				Logger.Error(e.ErrorStack())
			} else {
				Logger.Errorf("%s %s", reflect.TypeOf(err).String(), err.Error())
			}
		}
	}
	_, err := conf.Scheduler.Every(interval).Minutes().Do(update)
	if err != nil {
		return err
	}
	// Run first update after a small delay
	go func() {
		<-time.NewTimer(200 * time.Millisecond).C
		update()
	}()
	return nil
}

func (conf *Configuration) UpdateSchemes() error {
	for _, scheme := range conf.SchemeManagers {
		if err := conf.UpdateScheme(scheme, nil); err != nil {
			return err
		}
	}
	for _, scheme := range conf.RequestorSchemes {
		if err := conf.UpdateScheme(scheme, nil); err != nil {
			return err
		}
	}
	return nil
}

// UpdateScheme syncs the stored version within the irma_configuration directory
// with the remote version at the scheme's URL, downloading and storing
// new and modified files, according to the index files of both versions.
// It stores the identifiers of new or updated entities in the second parameter.
func (conf *Configuration) UpdateScheme(scheme Scheme, downloaded *IrmaIdentifierSet) error {
	if conf.readOnly {
		return errors.New("cannot update a read-only configuration")
	}
	if scheme == nil {
		return errors.Errorf("Cannot update unknown scheme")
	}

	var (
		typ        = string(scheme.typ())
		id         = scheme.id()
		schemePath = scheme.path()
	)
	Logger.WithFields(logrus.Fields{"scheme": id, "type": typ}).Info("checking for updates")
	shouldUpdate, remoteState, err := conf.checkRemoteScheme(scheme)
	if err != nil {
		return err
	}
	if !shouldUpdate {
		return nil
	}

	// As long as we can write to the scheme directory, we guarantee that either
	// - updating succeeded, and the updated scheme on disk has been verified and parsed
	//   without error into the correct conf instance.
	// - if any error occurs, then neither the scheme on disk nor its data in the current
	//   conf instance is touched.
	// We do this by creating a temporary copy on disk of the scheme, which we then update,
	// verify, and parse into another *Configuration instance. Only after all possible errors have
	// occurred do we modify the scheme on disk and in memory.

	// copy the scheme on disk to a new temporary directory
	dir, newSchemePath, err := conf.tempSchemeCopy(scheme)
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	if err = conf.writeSchemeIndex(newSchemePath, remoteState.indexBytes, remoteState.signatureBytes); err != nil {
		return err
	}

	// iterate over the index and download new and changed files into the temp dir
	if err = conf.updateSchemeFiles(scheme, remoteState.index, newSchemePath, downloaded); err != nil {
		return err
	}

	// verify the updated scheme in the temp dir
	var newconf *Configuration
	if newconf, err = NewConfiguration(dir, ConfigurationOptions{}); err != nil {
		return err
	}
	if scheme, err = newconf.ParseSchemeFolder(newSchemePath); err != nil {
		return err
	}
	if err = scheme.update(); err != nil {
		return err
	}

	// replace old scheme on disk with the new one from the temp dir
	if err = conf.updateSchemeDir(scheme, schemePath, newSchemePath); err != nil {
		return err
	}

	scheme.purge(conf)
	conf.join(newconf)
	return nil
}

func (conf *Configuration) IsInAssets(scheme Scheme) (bool, error) {
	if conf.assets == "" {
		return false, nil
	}
	_, exists, err := common.Stat(path.Join(conf.assets, scheme.id()))
	return exists, err
}

// DangerousDeleteScheme deletes the given scheme from the configuration.
// Be aware: this action is dangerous when the scheme is still in use.
func (conf *Configuration) DangerousDeleteScheme(scheme Scheme) error {
	exists, err := conf.IsInAssets(scheme)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("cannot delete scheme that is included in assets")
	}
	return scheme.delete(conf)
}

func (conf *Configuration) ParseSchemeFolder(dir string) (scheme Scheme, serr error) {
	var (
		status SchemeManagerStatus
		err    error
		id     string
	)
	scheme, status, err = conf.parseSchemeDescription(dir)
	if scheme != nil {
		id = scheme.id()
	}
	if err != nil {
		serr = &SchemeManagerError{Scheme: id, Status: status, Err: err}
		return
	}

	// From this point, we keep the scheme in our map even if it has an error. The user must check that
	// scheme.Status == SchemeManagerStatusValid, aka "Valid" before using any scheme for
	// anything, and handle accordingly.
	scheme.add(conf)
	defer func() {
		if serr != nil {
			scheme.setStatus(serr.(*SchemeManagerError).Status)
		}
		scheme.addError(conf, serr)
	}()

	// validate scheme contents
	if status, err := scheme.validate(conf); err != nil {
		serr = &SchemeManagerError{Scheme: id, Status: status, Err: err}
		return
	}
	err = scheme.parseContents(conf)
	if err != nil {
		serr = &SchemeManagerError{Scheme: id, Err: err, Status: SchemeManagerStatusContentParsingError}
		return
	}
	scheme.setStatus(SchemeManagerStatusValid)
	return
}

// Unexported scheme helpers that work for all scheme types (issuer or requestor) follow.
// These deal with what schemes have in common: verifying the signature; authenticating
// contained files against the (signed) index; and downloading, (re)installing
// and updating them against the remote.
// The code that deals with the scheme contents, of which the structure differs per scheme type,
// is found further below as helpers on the scheme structs. This includes modifying the
// various maps on Configuration instances.

func (conf *Configuration) updateSchemeFiles(
	scheme Scheme, index SchemeManagerIndex, newschemepath string, downloaded *IrmaIdentifierSet,
) error {
	var (
		transport = NewHTTPTransport(scheme.url(), true)
		oldIndex  = scheme.idx()
		id        = scheme.id()
	)
	for path, newHash := range index {
		pathStripped := path[len(id)+1:] // strip scheme name
		fullpath := filepath.Join(newschemepath, pathStripped)
		oldHash, known := oldIndex[path]
		var have bool
		have, err := common.PathExists(fullpath)
		if err != nil {
			return err
		}
		if known && have && oldHash.Equal(newHash) {
			continue // nothing to do, we already have this file
		}
		// Ensure that the folder in which to write the file exists
		if err = os.MkdirAll(filepath.Dir(fullpath), 0700); err != nil {
			return err
		}
		// Download the new file, store it in our scheme
		var bts []byte
		if bts, err = downloadSignedFile(transport, newschemepath, pathStripped, newHash); err != nil {
			return err
		}
		// handle file contents per scheme type
		if err = scheme.handleUpdateFile(conf, newschemepath, pathStripped, bts, transport, downloaded); err != nil {
			return err
		}
	}
	return nil
}

func (conf *Configuration) parseSchemeDescription(dir string) (Scheme, SchemeManagerStatus, error) {
	filename, err := common.SchemeFilename(dir)
	if err != nil {
		return nil, SchemeManagerStatusParsingError, err
	}

	index, _, err := conf.parseIndex(dir)
	if err != nil {
		return nil, SchemeManagerStatusParsingError, err
	}
	bts, found, err := conf.readSignedFile(index, dir, filename)
	if !found {
		return nil, SchemeManagerStatusParsingError, errors.New("scheme file not found in index")
	}
	if err != nil {
		return nil, SchemeManagerStatusParsingError, err
	}

	_, typ, err := common.SchemeInfo(filename, bts)
	if err != nil {
		return nil, SchemeManagerStatusParsingError, err
	}

	scheme := newScheme(SchemeType(typ))
	scheme.setIdx(index)
	scheme.setPath(dir)

	// read scheme description
	var exists bool
	exists, err = conf.parseSchemeFile(scheme, filename, scheme)
	if err != nil || !exists {
		return scheme, SchemeManagerStatusParsingError, err
	}
	if index.Scheme() != scheme.id() {
		return scheme, SchemeManagerStatusParsingError, errors.Errorf("cannot use index of scheme %s for scheme %s", index.Scheme(), scheme.id())
	}

	var ts *Timestamp
	ts, exists, err = readTimestamp(filepath.Join(dir, "timestamp"))
	if err != nil {
		return scheme, SchemeManagerStatusParsingError, WrapErrorPrefix(err, "could not read scheme manager timestamp")
	}
	if !exists {
		return scheme, SchemeManagerStatusParsingError, errors.New("scheme manager timestamp not found")
	}
	scheme.setTimestamp(*ts)

	return scheme, SchemeManagerStatusValid, nil
}

func (conf *Configuration) parseSchemeFile(
	scheme Scheme, path string, description interface{},
) (bool, error) {
	abs := filepath.Join(scheme.path(), path)
	if _, err := os.Stat(abs); err != nil {
		return false, nil
	}

	bts, found, err := conf.readSignedFile(scheme.idx(), scheme.path(), path)
	if !found {
		return false, errors.Errorf("File %s (%s) not present in scheme index", path, abs)
	}
	if err != nil {
		return true, err
	}

	return true, common.Unmarshal(filepath.Base(path), bts, description)
}

func (conf *Configuration) reinstallScheme(scheme Scheme) (err error) {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}
	defer func() {
		scheme.deleteError(conf, err)
	}()

	// first try remote
	if err = conf.reinstallSchemeFromRemote(scheme); err == nil {
		return nil
	}
	// didn't work, try from assets
	err = conf.reinstallSchemeFromAssets(scheme)
	return
}

func (conf *Configuration) reinstallSchemeFromAssets(scheme Scheme) error {
	if err := scheme.delete(conf); err != nil {
		return err
	}
	if _, err := conf.copyFromAssets(filepath.Base(scheme.path())); err != nil {
		return err
	}
	_, err := conf.ParseSchemeFolder(scheme.path())
	return err
}

func (conf *Configuration) reinstallSchemeFromRemote(scheme Scheme) error {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}
	pkbts, err := os.ReadFile(filepath.Join(scheme.path(), "pk.pem"))
	if err != nil {
		return err
	}
	if err = scheme.delete(conf); err != nil {
		return err
	}
	return conf.installScheme(scheme.url(), pkbts, filepath.Base(scheme.path()))
}

// newSchemeDir returns the name of a newly created directory into which a scheme can be installed:
// the parameter dir if specified, otherwise the first of the following that does not already exist:
// $scheme, $scheme-0, $scheme-1, ...
func (conf *Configuration) newSchemeDir(id, dir string) (string, error) {
	dirGiven := dir != ""
	if !dirGiven {
		dir = id
	}

	path := filepath.Join(conf.Path, dir)
	exists, err := common.PathExists(path)
	if err != nil {
		return "", err
	}
	if !exists {
		return path, common.EnsureDirectoryExists(path)
	}
	if dirGiven {
		return "", errors.New("cannot install scheme: specified directory not empty")
	}
	for i := 0; ; i++ {
		path = filepath.Join(conf.Path, dir+"-"+strconv.Itoa(i))
		exists, err := common.PathExists(dir)
		if err != nil {
			return "", err
		}
		if !exists {
			return path, common.EnsureDirectoryExists(path)
		}
	}
}

func (conf *Configuration) installScheme(url string, publickey []byte, dir string) (err error) {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}

	scheme, err := downloadScheme(url)
	if err != nil {
		return err
	}
	id := scheme.id()
	if scheme.present(id, conf) {
		return errors.New("cannot install an already existing scheme")
	}

	// In the code below, newSchemeDir makes a new directory for the configuration.
	// If an error occurs hereafter, we remove this directory again to prevent side effects.
	// This approach is not resistant to this function being stopped unexpectedly.
	dirPath, err := conf.newSchemeDir(id, dir)
	scheme.setPath(dirPath)
	defer func() {
		if err != nil && dirPath != "" {
			_ = scheme.delete(conf)
		}
	}()
	if err != nil {
		return
	}

	if publickey != nil {
		if err = common.SaveFile(filepath.Join(dirPath, "pk.pem"), publickey); err != nil {
			return
		}
	} else {
		if _, err = downloadFile(NewHTTPTransport(url, true), dirPath, "pk.pem"); err != nil {
			return
		}
	}

	if scheme.id() != id {
		return errors.Errorf("scheme has id %s but expected %s", scheme.id(), id)
	}

	scheme.add(conf)
	return conf.UpdateScheme(scheme, nil)
}

type remoteSchemeState struct {
	scheme Scheme

	timestamp      *Timestamp
	timestampBytes []byte

	index      SchemeManagerIndex
	indexBytes []byte

	signatureBytes []byte
}

func (conf *Configuration) checkRemoteScheme(scheme Scheme) (bool, *remoteSchemeState, error) {
	remoteState, err := conf.checkRemoteTimestamp(scheme)
	if err != nil {
		return false, nil, err
	}
	id := scheme.id()
	typ := string(scheme.typ())
	timestampdiff := int64(remoteState.timestamp.Sub(scheme.timestamp()))
	if timestampdiff == 0 {
		Logger.WithFields(logrus.Fields{"scheme": id, "type": typ}).Info("scheme is up-to-date, not updating")
		return false, remoteState, nil
	} else if timestampdiff < 0 {
		Logger.WithFields(logrus.Fields{"scheme": id, "type": typ}).Info("local scheme is newer than remote, not updating")
		return false, remoteState, nil
	}
	// timestampdiff > 0
	Logger.WithFields(logrus.Fields{"scheme": id, "type": typ}).Info("scheme is outdated, updating")

	return true, remoteState, nil
}

func (conf *Configuration) checkRemoteTimestamp(scheme Scheme) (*remoteSchemeState, error) {
	t := NewHTTPTransport(scheme.url(), true)
	indexbts, err := t.GetBytes("index")
	if err != nil {
		return nil, err
	}
	sig, err := t.GetBytes("index.sig")
	if err != nil {
		return nil, err
	}
	timestampbts, err := t.GetBytes("timestamp")
	if err != nil {
		return nil, err
	}
	pk, err := conf.schemePublicKey(scheme.path())
	if err != nil {
		return nil, err
	}

	// Verify signature and the timestamp hash in the index
	if err = signed.Verify(pk, indexbts, sig); err != nil {
		return nil, err
	}
	index := SchemeManagerIndex(make(map[string]SchemeFileHash))
	if err = index.FromString(string(indexbts)); err != nil {
		return nil, err
	}
	sha := sha256.Sum256(timestampbts)
	if !bytes.Equal(index[scheme.id()+"/timestamp"], sha[:]) {
		return nil, errors.Errorf("signature over timestamp is not valid")
	}

	timestamp, err := parseTimestamp(timestampbts)
	if err != nil {
		return nil, err
	}

	return &remoteSchemeState{scheme, timestamp, timestampbts, index, indexbts, sig}, nil
}

func (conf *Configuration) writeSchemeIndex(dest string, indexbts, sigbts []byte) error {
	if err := common.EnsureDirectoryExists(dest); err != nil {
		return err
	}
	if err := common.SaveFile(filepath.Join(dest, "index"), indexbts); err != nil {
		return err
	}
	return common.SaveFile(filepath.Join(dest, "index.sig"), sigbts)
}

func (conf *Configuration) isUpToDate(subdir string) (bool, error) {
	if conf.assets == "" || conf.readOnly {
		return true, nil
	}
	newTime, exists, err := readTimestamp(filepath.Join(conf.assets, subdir, "timestamp"))
	if err != nil {
		return true, WrapErrorPrefix(err, "could not read asset timestamp of scheme "+subdir)
	}
	if !exists {
		return true, errors.Errorf("no timestamp found for scheme %s", subdir)
	}

	// The storage version of the manager does not need to have a timestamp. If it does not, it is outdated.
	oldTime, exists, err := readTimestamp(filepath.Join(conf.Path, subdir, "timestamp"))
	if err != nil {
		return true, err
	}
	return exists && !newTime.After(*oldTime), nil
}

func (conf *Configuration) copyFromAssets(subdir string) (bool, error) {
	if conf.assets == "" || conf.readOnly {
		return false, nil
	}
	// Remove old version; we want an exact copy of the assets version
	// not a merge of the assets version and the storage version
	if err := os.RemoveAll(filepath.Join(conf.Path, subdir)); err != nil {
		return false, err
	}
	return true, common.CopyDirectory(
		filepath.Join(conf.assets, subdir),
		filepath.Join(conf.Path, subdir),
	)
}

// verifySignature verifies the signature on the scheme index file
// (which contains the SHA256 hashes of all files under this scheme,
// which are used for verifying file authenticity).
func (conf *Configuration) verifySignature(dir string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = errors.Errorf("Scheme manager index signature failed to verify: %s", e.Error())
			} else {
				err = errors.New("Scheme manager index signature failed to verify")
			}
		}
	}()

	if err := common.AssertPathExists(filepath.Join(dir, "index"), filepath.Join(dir, "index.sig"), filepath.Join(dir, "pk.pem")); err != nil {
		return errors.New("Missing scheme manager index file, signature, or public key")
	}

	// Read and hash index file
	indexbts, err := os.ReadFile(filepath.Join(dir, "index"))
	if err != nil {
		return err
	}

	// Read and parse scheme public key
	pk, err := conf.schemePublicKey(dir)
	if err != nil {
		return err
	}

	// Read and parse signature
	sig, err := os.ReadFile(filepath.Join(dir, "index.sig"))
	if err != nil {
		return err
	}

	return signed.Verify(pk, indexbts, sig)
}

func (conf *Configuration) schemePublicKey(dir string) (*ecdsa.PublicKey, error) {
	pkbts, err := os.ReadFile(filepath.Join(dir, "pk.pem"))
	if err != nil {
		return nil, err
	}
	return signed.UnmarshalPemPublicKey(pkbts)
}

// readSignedFile reads the file at the specified path
// and verifies its authenticity by checking that the file hash
// is present in the (signed) scheme index file.
func (conf *Configuration) readSignedFile(index SchemeManagerIndex, base string, path string) ([]byte, bool, error) {
	signedHash, ok := index[index.Scheme()+"/"+filepath.ToSlash(path)]
	if !ok {
		return nil, false, nil
	}

	bts, err := conf.readHashedFile(filepath.Join(base, path), signedHash)
	return bts, true, err
}

func (conf *Configuration) readHashedFile(path string, hash SchemeFileHash) ([]byte, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	computedHash := sha256.Sum256(bts)

	if !bytes.Equal(computedHash[:], hash) {
		return nil, errors.Errorf("Hash of %s does not match scheme manager index", path)
	}
	return bts, nil
}

// parseIndex parses the index file of the specified manager.
func (conf *Configuration) parseIndex(dir string) (SchemeManagerIndex, SchemeManagerStatus, error) {
	if err := conf.verifySignature(dir); err != nil {
		return nil, SchemeManagerStatusInvalidSignature, err
	}
	path := filepath.Join(dir, "index")
	if err := common.AssertPathExists(path); err != nil {
		return nil, SchemeManagerStatusInvalidIndex, fmt.Errorf("missing scheme manager index file; tried %s", path)
	}
	indexbts, err := os.ReadFile(path)
	if err != nil {
		return nil, SchemeManagerStatusInvalidIndex, err
	}
	index := SchemeManagerIndex(make(map[string]SchemeFileHash))
	if err = index.FromString(string(indexbts)); err != nil {
		return nil, SchemeManagerStatusInvalidIndex, err
	}
	if err = conf.checkUnsignedFiles(dir, index); err != nil {
		return nil, SchemeManagerStatusContentParsingError, err
	}
	return index, SchemeManagerStatusValid, nil
}

func (conf *Configuration) checkUnsignedFiles(dir string, index SchemeManagerIndex) error {
	return common.WalkDir(dir, func(path string, info os.FileInfo) error {
		relpath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		schemepath := filepath.Join(index.Scheme(), relpath)

		// On Linux and MacOS, filepath.Rel returns a path with forward slashes, on Windows with backslashes.
		// However, scheme index is always stored with forward slashes, so we need to convert the path to forward slashes.
		schemepath = filepath.ToSlash(schemepath)

		for _, ex := range sigExceptions {
			if ex.MatchString(schemepath) {
				return nil
			}
		}

		if info.IsDir() {
			if !dirInScheme(index, schemepath) {
				conf.Warnings = append(conf.Warnings, "Ignored dir: "+schemepath)
			}
		} else {
			if _, ok := index[schemepath]; !ok {
				conf.Warnings = append(conf.Warnings, "Ignored file: "+schemepath)
			}
		}

		return nil
	})
}

func downloadSignedFile(
	transport *HTTPTransport, base, path string, hash SchemeFileHash,
) ([]byte, error) {
	b, err := transport.GetBytes(path)
	if err != nil {
		return nil, err
	}
	sha := sha256.Sum256(b)
	if hash != nil && !bytes.Equal(hash, sha[:]) {
		return nil, errors.Errorf("Signature over new file %s is not valid", path)
	}
	dest := filepath.Join(base, filepath.FromSlash(path))
	if err = common.EnsureDirectoryExists(filepath.Dir(dest)); err != nil {
		return nil, err
	}
	return b, common.SaveFile(dest, b)
}

func downloadFile(transport *HTTPTransport, base, path string) ([]byte, error) {
	return downloadSignedFile(transport, base, path, nil)
}

func dirInScheme(index SchemeManagerIndex, dir string) bool {
	for indexpath := range index {
		if strings.HasPrefix(indexpath, dir) {
			return true
		}
	}
	return false
}

func downloadScheme(url string) (Scheme, error) {
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}

	var filenames = common.SchemeFilenames
	for _, filename := range common.SchemeFilenames {
		if strings.HasSuffix(url, "/"+filename) {
			filenames = []string{filename}
		}
	}

	var scheme Scheme
	for _, filename := range filenames {
		u := url
		if strings.HasSuffix(url, "/"+filename) {
			u = url[:len(url)-1-len(filename)]
		}
		b, err := NewHTTPTransport(u, true).GetBytes(filename)
		if err != nil {
			if err.(*SessionError).RemoteStatus == 404 {
				continue
			}
			return nil, err
		}

		_, typ, err := common.SchemeInfo(filename, b)
		if err != nil {
			return nil, err
		}
		scheme = newScheme(SchemeType(typ))
		return scheme, common.Unmarshal(filename, b, scheme)
	}

	return nil, errors.New("no scheme description file found")
}

func (conf *Configuration) tempSchemeCopy(scheme Scheme) (string, string, error) {
	dir, err := os.MkdirTemp(filepath.Dir(scheme.path()), ".tempscheme")
	if err != nil {
		return "", "", err
	}
	newschemepath := filepath.Join(dir, scheme.id())
	if err = common.EnsureDirectoryExists(newschemepath); err != nil {
		return "", "", err
	}
	if err = common.CopyDirectory(scheme.path(), newschemepath); err != nil {
		return "", "", err
	}
	return dir, newschemepath, nil
}

// Move oldscheme to a temp dir in the same directory als oldscheme;
// move newscheme to the location of oldscheme; and delete oldscheme.
// If the first move works then the second one should too, so this will either entirely succeed
// or leave the old scheme untouched.
func (conf *Configuration) updateSchemeDir(scheme Scheme, oldscheme, newscheme string) error {
	// Create a directory in the same directory as oldscheme,
	// this is to make sure os.Rename does not fail with an "invalid cross-device link" error.
	tmp, err := os.MkdirTemp(filepath.Dir(oldscheme), ".oldscheme")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmp)
	}()
	if err = os.Rename(oldscheme, filepath.Join(tmp, scheme.id())); err != nil {
		return err
	}
	if err = os.Rename(newscheme, oldscheme); err != nil {
		return err
	}
	scheme.setPath(oldscheme)
	return nil
}

var (
	// These files never occur in a scheme's index
	sigExceptions = []*regexp.Regexp{
		regexp.MustCompile(`/.git(/.*)?`),
		regexp.MustCompile(`^.*?/pk\.pem$`),
		regexp.MustCompile(`^.*?/sk\.pem$`),
		regexp.MustCompile(`^.*?/index`),
		regexp.MustCompile(`^.*?/index\.sig`),
		regexp.MustCompile(`^.*?/AUTHORS$`),
		regexp.MustCompile(`^.*?/LICENSE$`),
		regexp.MustCompile(`^.*?/README\.md$`),
		regexp.MustCompile(`^.*?/.*?/PrivateKeys$`),
		regexp.MustCompile(`^.*?/.*?/PrivateKeys/\d+.xml$`),
		regexp.MustCompile(`^.*?/assets/?\w*(\.png)?$`),
		regexp.MustCompile(`\.DS_Store$`),
	}

	issPattern  = regexp.MustCompile(`^([^/]+)/description\.xml`)
	credPattern = regexp.MustCompile(`([^/]+)/Issues/([^/]+)/description\.xml`)
	keyPattern  = regexp.MustCompile(`([^/]+)/PublicKeys/(\d+)\.xml`)
)

func newScheme(typ SchemeType) Scheme {
	switch typ {
	case SchemeTypeIssuer:
		return &SchemeManager{Status: SchemeManagerStatusUnprocessed}
	case SchemeTypeRequestor:
		return &RequestorScheme{Status: SchemeManagerStatusUnprocessed}
	default:
		panic("newScheme() does not support scheme type " + typ)
	}
}

// Identifier returns the identifier of the specified scheme.
func (scheme *SchemeManager) Identifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(scheme.ID)
}

// Distributed indicates if this scheme uses a keyshare server.
func (scheme *SchemeManager) Distributed() bool {
	return len(scheme.KeyshareServer) > 0
}

func (scheme *SchemeManager) id() string { return scheme.ID }

func (scheme *SchemeManager) idx() SchemeManagerIndex { return scheme.index }

func (scheme *SchemeManager) setIdx(idx SchemeManagerIndex) { scheme.index = idx }

func (scheme *SchemeManager) url() string { return scheme.URL }

func (scheme *SchemeManager) timestamp() Timestamp { return scheme.Timestamp }

func (scheme *SchemeManager) setTimestamp(t Timestamp) { scheme.Timestamp = t }

func (scheme *SchemeManager) setStatus(s SchemeManagerStatus) { scheme.Status = s }

func (scheme *SchemeManager) path() string { return scheme.storagepath }

func (scheme *SchemeManager) setPath(path string) { scheme.storagepath = path }

func (scheme *SchemeManager) parseContents(conf *Configuration) error {
	err := common.IterateSubfolders(scheme.path(), func(dir string, _ os.FileInfo) error {
		issuer := &Issuer{}

		exists, err := conf.parseSchemeFile(scheme, filepath.Join(filepath.Base(dir), "description.xml"), issuer)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if issuer.XMLVersion < 4 {
			return errors.New("Unsupported issuer description")
		}

		if len(issuer.Languages) == 0 {
			issuer.Languages = scheme.Languages
		}
		if err = conf.validateIssuer(scheme, issuer, dir); err != nil {
			return err
		}

		conf.Issuers[issuer.Identifier()] = issuer
		return scheme.parseCredentialsFolder(conf, issuer, filepath.Join(dir, "Issues"))
	})

	if err != nil {
		return err
	}

	// validate that there are no circular dependencies
	for _, credType := range conf.CredentialTypes {
		if credType.SchemeManagerID == scheme.ID {
			if err := credType.validateDependencies(conf, []CredentialTypeIdentifier{}, credType.Identifier()); err != nil {
				return err
			}
		}
	}

	return nil
}

var (
	errCircDep = errors.Errorf("No valid dependency branch could be built. There might be a circular dependency.")
)

func (ct CredentialType) validateDependencies(conf *Configuration, validatedDeps DependencyChain, toBeChecked CredentialTypeIdentifier) error {
	if len(validatedDeps) >= maxDepComplexity {
		return errors.New("dependency tree too complex: " + validatedDeps.String())
	}
	for _, discon := range conf.CredentialTypes[ct.Identifier()].Dependencies {
		disconSatisfied := false
		for _, con := range discon {
			conSatisfied := true

			for _, item := range con {
				if conf.CredentialTypes[item].SchemeManagerID != ct.SchemeManagerID {
					return errors.Errorf("credential type %s in scheme %s has dependency outside the scheme: %s",
						ct.Identifier().String(), ct.SchemeManagerID, conf.CredentialTypes[item].Identifier().String())
				}

				// all items need to be valid for middle to be valid
				if toBeChecked == item {
					conSatisfied = false
					break
				}

				if conf.CredentialTypes[item].Dependencies != nil {
					if e := conf.CredentialTypes[item].validateDependencies(conf, append(validatedDeps, item), toBeChecked); e != nil {
						if e == errCircDep {
							conSatisfied = false
							break
						} else {
							return e
						}
					}
				}
			}
			if conSatisfied {
				disconSatisfied = true
			}
		}

		if !disconSatisfied {
			return errCircDep
		}
	}

	return nil
}

func (d DependencyChain) String() string {
	deps := make([]string, len(d))
	for i := 0; i < len(d); i++ {
		deps[i] = d[i].String()
	}
	return strings.Join(deps, ", ")
}

func (scheme *SchemeManager) validate(conf *Configuration) (SchemeManagerStatus, error) {
	if scheme.XMLVersion < 7 {
		return SchemeManagerStatusParsingError, errors.New("Unsupported scheme manager description")
	}
	if scheme.KeyshareServer != "" {
		if err := common.AssertPathExists(filepath.Join(scheme.path(), "kss-0.pem")); err != nil {
			return SchemeManagerStatusParsingError, errors.Errorf("Scheme %s has keyshare URL but no keyshare public key kss-0.pem", scheme.ID)
		}
	}
	conf.validateTranslations(fmt.Sprintf("Scheme %s", scheme.ID), scheme, scheme.Languages)

	// Verify that all other files are validly signed
	if err := scheme.verifyFiles(conf); err != nil {
		return SchemeManagerStatusInvalidSignature, err
	}

	return SchemeManagerStatusValid, nil
}

func (scheme *SchemeManager) update() error {
	return scheme.downloadDemoPrivateKeys()
}

func (scheme *SchemeManager) handleUpdateFile(conf *Configuration, _, filename string, _ []byte, _ *HTTPTransport, downloaded *IrmaIdentifierSet) error {
	// See if the file is a credential type or issuer, and add it to the downloaded set if so
	if downloaded == nil {
		return nil
	}
	var matches []string
	matches = issPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 2 {
		issid := NewIssuerIdentifier(fmt.Sprintf("%s.%s", scheme.id(), matches[1]))
		downloaded.Issuers[issid] = struct{}{}
	}
	matches = credPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 3 {
		credid := NewCredentialTypeIdentifier(fmt.Sprintf("%s.%s.%s", scheme.id(), matches[1], matches[2]))
		downloaded.CredentialTypes[credid] = struct{}{}
	}
	matches = keyPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 3 {
		issid := NewIssuerIdentifier(fmt.Sprintf("%s.%s", scheme.id(), matches[1]))
		counter, err := strconv.ParseUint(matches[2], 10, 32)
		if err != nil {
			return err
		}
		downloaded.PublicKeys[issid] = append(downloaded.PublicKeys[issid], uint(counter))
	}
	return nil
}

func (scheme *SchemeManager) delete(conf *Configuration) error {
	if conf.readOnly {
		return errors.New("cannot delete scheme from a read-only configuration")
	}

	id := scheme.Identifier()
	delete(conf.SchemeManagers, id)
	delete(conf.DisabledSchemeManagers, id)
	name := id.String()
	for iss := range conf.Issuers {
		if iss.Root() == name {
			delete(conf.Issuers, iss)
		}
	}
	conf.publicKeys.DeleteIf(func(id PublicKeyIdentifier, _ *gabikeys.PublicKey) bool {
		return id.Issuer.Root() == name
	})
	for cred := range conf.CredentialTypes {
		if cred.Root() == name {
			delete(conf.CredentialTypes, cred)
		}
	}

	return os.RemoveAll(scheme.path())
}

func (scheme *SchemeManager) add(conf *Configuration) {
	scheme.purge(conf)
	conf.SchemeManagers[scheme.Identifier()] = scheme
}

func (scheme *SchemeManager) addError(conf *Configuration, err error) {
	if err == nil {
		return
	}
	switch serr := err.(type) {
	case *SchemeManagerError:
		conf.DisabledSchemeManagers[scheme.Identifier()] = serr
	default:
		conf.DisabledSchemeManagers[scheme.Identifier()] = &SchemeManagerError{
			Scheme: scheme.id(),
			Status: SchemeManagerStatusParsingError,
			Err:    err,
		}
	}
}

func (scheme *SchemeManager) deleteError(conf *Configuration, err error) {
	if err != nil {
		return
	}
	delete(conf.DisabledSchemeManagers, scheme.Identifier())
}

func (scheme *SchemeManager) present(id string, conf *Configuration) bool {
	return conf.SchemeManagers[NewSchemeManagerIdentifier(id)] != nil
}

func (*SchemeManager) typ() SchemeType { return SchemeTypeIssuer }

func (scheme *SchemeManager) purge(conf *Configuration) {
	id := scheme.Identifier()
	delete(conf.SchemeManagers, id)
	delete(conf.DisabledSchemeManagers, id)
	delete(conf.kssPublicKeys, id)
	for issuerid, issuer := range conf.Issuers {
		if issuer.SchemeManagerIdentifier() == id {
			delete(conf.Issuers, issuerid)
			conf.publicKeys.DeleteIf(func(keyid PublicKeyIdentifier, _ *gabikeys.PublicKey) bool {
				return keyid.Issuer.SchemeManagerIdentifier() == id
			})
		}
	}
	for credid, cred := range conf.CredentialTypes {
		if cred.SchemeManagerIdentifier() == id {
			delete(conf.CredentialTypes, credid)
		}
	}
	for attrid, attr := range conf.AttributeTypes {
		if attr.SchemeManagerID == id.String() {
			delete(conf.AttributeTypes, attrid)
		}
	}
	for hash, credid := range conf.reverseHashes {
		if credid.Root() == id.String() {
			delete(conf.reverseHashes, hash)
		}
	}
}

func (scheme *SchemeManager) verifyFiles(conf *Configuration) error {
	for file := range scheme.index {
		file = file[len(scheme.id())+1:] // strip scheme name
		exists, err := common.PathExists(filepath.Join(scheme.path(), file))
		if err != nil {
			return err
		}
		if !exists {
			return errors.Errorf("file %s in index is not found on disk", file)
		}
		// Don't care about the actual bytes
		if _, _, err = conf.readSignedFile(scheme.index, scheme.path(), file); err != nil {
			return err
		}
	}

	return nil
}

// parse $schememanager/$issuer/Issues/*/description.xml
func (scheme *SchemeManager) parseCredentialsFolder(conf *Configuration, issuer *Issuer, path string) error {
	var foundcred bool
	err := common.IterateSubfolders(path, func(dir string, _ os.FileInfo) error {
		cred := &CredentialType{}
		rel, err := filepath.Rel(scheme.path(), filepath.Join(dir, "description.xml"))
		if err != nil {
			return err
		}
		exists, err := conf.parseSchemeFile(scheme, rel, cred)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if len(cred.Languages) == 0 {
			cred.Languages = issuer.Languages
		}
		if err = conf.validateCredentialType(scheme, issuer, cred, dir); err != nil {
			return err
		}
		foundcred = true
		if cred.RevocationUpdateCount == 0 {
			cred.RevocationUpdateCount = RevocationParameters.DefaultUpdateEventCount
		}
		if cred.RevocationUpdateSpeed == 0 {
			cred.RevocationUpdateSpeed = RevocationParameters.ClientDefaultUpdateSpeed
		}
		for i, url := range cred.RevocationServers {
			if url[len(url)-1] == '/' {
				cred.RevocationServers[i] = url[:len(url)-1]
			}
		}
		credid := cred.Identifier()
		conf.CredentialTypes[credid] = cred
		conf.addReverseHash(credid)
		revAttrs := false
		for index, attr := range cred.AttributeTypes {
			attr.Index = index
			attr.SchemeManagerID = cred.SchemeManagerID
			attr.IssuerID = cred.IssuerID
			attr.CredentialTypeID = cred.ID
			conf.AttributeTypes[attr.GetAttributeTypeIdentifier()] = attr

			if attr.ID != "" && attr.RevocationAttribute {
				return errors.New(fmt.Sprintf("Attribute %s.%s cannot contain revocation=\"true\". This needs to be a separate attribute: <Attribute revocation=\"true\" />", attr.IssuerID, attr.ID))
			}

			if attr.RevocationAttribute {
				revAttrs = true
			}
		}

		if len(cred.RevocationServers) == 0 && revAttrs {
			return errors.New("Revocation attribute specified, but RevocationServer is missing")
		}
		if len(cred.RevocationServers) > 0 && !revAttrs {
			return errors.New("RevocationServer specified, but revocation attribute: '<Attribute revocation=\"true\" />' is missing")
		}

		return nil
	})
	if !foundcred {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no credential types", issuer.Identifier().String()))
	}
	return err
}

// downloadDemoPrivateKeys attempts to download the scheme and issuer private keys, if the scheme is
// a demo scheme and if they are not already present in the scheme, without failing if any of them
// is not available.
func (scheme *SchemeManager) downloadDemoPrivateKeys() error {
	if !scheme.Demo {
		return nil
	}

	Logger.WithField("scheme", scheme.ID).Debugf("Attempting downloading of private keys")
	transport := NewHTTPTransport(scheme.URL, true)

	_, err := downloadFile(transport, scheme.path(), "sk.pem")
	if err != nil { // If downloading of any of the private key fails just log it, and then continue
		Logger.WithField("scheme", scheme.ID).Warnf("Downloading scheme private key failed")
	}

	pkpath := filepath.Join(scheme.path(), "*", "PublicKeys", "*")
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return err
	}

	// For each public key, attempt to download a corresponding private key
	for _, file := range files {
		i := strings.LastIndex(pkpath, "PublicKeys")
		skpath := filepath.FromSlash(file[:i] + strings.Replace(file[i:], "PublicKeys", "PrivateKeys", 1))
		parts := strings.Split(skpath, string(filepath.Separator))
		exists, err := common.PathExists(skpath)
		if exists || err != nil {
			continue
		}
		remote := strings.Join(parts[len(parts)-3:], "/")
		if _, err = downloadFile(transport, scheme.path(), remote); err != nil {
			Logger.WithFields(logrus.Fields{"scheme": scheme.ID, "path": skpath}).
				Warnf("Downloading issuer private key failed: %s", err)
		}
	}

	return nil
}

func (scheme *RequestorScheme) id() string { return scheme.ID.String() }

func (scheme *RequestorScheme) idx() SchemeManagerIndex { return scheme.index }

func (scheme *RequestorScheme) setIdx(idx SchemeManagerIndex) { scheme.index = idx }

func (scheme *RequestorScheme) url() string { return scheme.URL }

func (scheme *RequestorScheme) timestamp() Timestamp { return scheme.Timestamp }

func (scheme *RequestorScheme) setTimestamp(t Timestamp) { scheme.Timestamp = t }

func (scheme *RequestorScheme) setStatus(s SchemeManagerStatus) { scheme.Status = s }

func (scheme *RequestorScheme) path() string { return scheme.storagepath }

func (scheme *RequestorScheme) setPath(path string) {
	scheme.storagepath = path

	// Rebase all logo paths
	for _, requestor := range scheme.requestors {
		requestor.LogoPath = nil
		logoPath := requestor.ResolveLogoPath(scheme)
		if logoPath != "" {
			requestor.LogoPath = &logoPath
		}
	}
}

func (scheme *RequestorScheme) parseContents(conf *Configuration) error {
	for _, requestor := range scheme.requestors {
		if logoPath := requestor.ResolveLogoPath(scheme); logoPath != "" {
			requestor.LogoPath = &logoPath
		}
		for _, hostname := range requestor.Hostnames {
			if _, ok := conf.Requestors[hostname]; ok {
				return errors.Errorf("Double occurrence of hostname %s", hostname)
			}
			conf.Requestors[hostname] = requestor
		}
		for id, wizard := range requestor.Wizards {
			if _, ok := conf.IssueWizards[id]; ok {
				return errors.Errorf("Double occurrence of issue wizard %s", id)
			}
			conf.IssueWizards[id] = wizard
		}
	}
	return nil
}

func (scheme *RequestorScheme) validate(conf *Configuration) (SchemeManagerStatus, error) {
	// Verify all files in index, reading the RequestorChunks
	var (
		requestors []*RequestorInfo
		err        error
		exists     bool
	)
	for file := range scheme.index {
		filename := filepath.Base(file)
		if filename == "description.json" || filename == "timestamp" {
			continue
		}
		var currentChunk RequestorChunk
		exists, err = conf.parseSchemeFile(scheme, file[len(scheme.id())+1:], &currentChunk)
		if !exists {
			return SchemeManagerStatusParsingError, errors.Errorf("file %s of requestor scheme %s in index but not found on disk", file, scheme.ID)
		}
		if err != nil {
			return SchemeManagerStatusParsingError, err
		}
		for _, v := range currentChunk {
			if v.Scheme != scheme.ID {
				return SchemeManagerStatusParsingError, errors.Errorf("Requestor %s has incorrect scheme %s", v.Name, v.Scheme)

			}
		}
		requestors = append(requestors, currentChunk...)
	}

	// Verify all requestors
	for _, requestor := range requestors {
		if len(requestor.Languages) == 0 {
			requestor.Languages = scheme.Languages
		}
		if scheme.Demo && len(requestor.Hostnames) > 0 {
			return SchemeManagerStatusParsingError, errors.New("Demo requestor has hostnames: only allowed for non-demo schemes")
		}
		if requestor.ID.RequestorSchemeIdentifier() != scheme.ID {
			return SchemeManagerStatusParsingError, errors.Errorf("requestor %s has incorrect ID", requestor.ID)
		}
		if requestor.Logo != nil {
			if status, err := scheme.checkLogo(conf, *requestor.Logo); err != nil {
				return status, err
			}
		}
		for id, wizard := range requestor.Wizards {
			if len(wizard.Languages) == 0 {
				wizard.Languages = requestor.Languages
			}
			if id != wizard.ID || id.RequestorIdentifier() != requestor.ID {
				return SchemeManagerStatusParsingError, errors.Errorf("issue wizard %s has incorrect ID", id)
			}
			if err = wizard.Validate(conf); err != nil {
				return SchemeManagerStatusParsingError, errors.Errorf("issue wizard %s: %w", id, err)
			}
			if wizard.Logo != nil {
				if status, err := scheme.checkLogo(conf, *wizard.Logo); err != nil {
					return status, err
				}
				path := filepath.Join(scheme.path(), "assets", *wizard.Logo+".png")
				wizard.LogoPath = &path
			}
		}
	}
	scheme.requestors = requestors

	return SchemeManagerStatusValid, nil
}

func (scheme *RequestorScheme) checkLogo(conf *Configuration, logo string) (SchemeManagerStatus, error) {
	var hash []byte
	hash, err := hex.DecodeString(logo)
	if err != nil {
		return SchemeManagerStatusParsingError, err
	}
	if _, err = conf.readHashedFile(filepath.Join(scheme.path(), "assets", logo+".png"), hash); err != nil {
		return SchemeManagerStatusInvalidSignature, err
	}
	return "", nil
}

func (scheme *RequestorScheme) update() error {
	return nil
}

func (scheme *RequestorScheme) handleUpdateFile(conf *Configuration, path, filename string, bts []byte, transport *HTTPTransport, downloaded *IrmaIdentifierSet) error {
	// Download logos if needed

	if filepath.Base(filename) == "description.json" || filepath.Base(filename) == "timestamp" {
		return nil
	}
	var (
		data RequestorChunk
		err  error
	)
	if err = json.Unmarshal(bts, &data); err != nil {
		return err
	}
	for _, requestor := range data {
		if requestor.Logo == nil {
			continue
		}
		var ok bool
		filename := *requestor.Logo + ".png"
		ok, err = common.PathExists(filepath.Join(path, "assets", filename))
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		var hash []byte
		hash, err = hex.DecodeString(*requestor.Logo)
		if err != nil {
			return err
		}

		urlPath, err := url.JoinPath("assets", filename)
		if err != nil {
			return err
		}
		if _, err = downloadSignedFile(transport, path, urlPath, hash); err != nil {
			return err
		}
	}
	if downloaded != nil {
		downloaded.RequestorSchemes[scheme.ID] = struct{}{}
	}
	return nil
}

func (scheme *RequestorScheme) delete(conf *Configuration) error {
	if conf.readOnly {
		return errors.New("cannot delete scheme from a read-only configuration")
	}
	scheme.purge(conf)

	return os.RemoveAll(scheme.path())
}

func (scheme *RequestorScheme) add(conf *Configuration) {
	scheme.purge(conf)
	conf.RequestorSchemes[scheme.ID] = scheme
}

func (scheme *RequestorScheme) addError(conf *Configuration, err error) {
	if err == nil {
		return
	}
	switch serr := err.(type) {
	case *SchemeManagerError:
		conf.DisabledRequestorSchemes[scheme.ID] = serr
	default:
		conf.DisabledRequestorSchemes[scheme.ID] = &SchemeManagerError{
			Scheme: scheme.id(),
			Status: SchemeManagerStatusParsingError,
			Err:    err,
		}
	}

}

func (scheme *RequestorScheme) deleteError(conf *Configuration, err error) {
	if err != nil {
		return
	}
	delete(conf.DisabledRequestorSchemes, scheme.ID)
}

func (scheme *RequestorScheme) present(id string, conf *Configuration) bool {
	return conf.RequestorSchemes[NewRequestorSchemeIdentifier(id)] != nil
}

func (*RequestorScheme) typ() SchemeType { return SchemeTypeRequestor }

// purge removes a requestor scheme and its requestors from the configuration
func (scheme *RequestorScheme) purge(conf *Configuration) {
	for k, v := range conf.Requestors {
		if v.Scheme == scheme.ID {
			delete(conf.Requestors, k)
		}
	}
	delete(conf.RequestorSchemes, scheme.ID)
	delete(conf.DisabledRequestorSchemes, scheme.ID)
}

func (i SchemeManagerIndex) String() string {
	var paths []string
	var b bytes.Buffer

	for path := range i {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		b.WriteString(hex.EncodeToString(i[path]))
		b.WriteString(" ")
		b.WriteString(path)
		b.WriteString("\n")
	}

	return b.String()
}

// FromString populates this index by parsing the specified string.
func (i SchemeManagerIndex) FromString(s string) error {
	for j, line := range strings.Split(s, "\n") {
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			return errors.Errorf("Scheme manager index line %d has incorrect amount of parts", j)
		}
		hash, err := hex.DecodeString(parts[0])
		if err != nil {
			return err
		}
		i[parts[1]] = hash
	}

	return nil
}

func (i SchemeManagerIndex) Scheme() string {
	for p := range i {
		return p[0:strings.Index(p, "/")]
	}
	return ""
}

func (hash SchemeFileHash) String() string {
	return hex.EncodeToString(hash)
}

func (hash SchemeFileHash) Equal(other SchemeFileHash) bool {
	return bytes.Equal(hash, other)
}

func (sme SchemeManagerError) Error() string {
	return fmt.Sprintf("Error parsing scheme manager %s: %s", sme.Scheme, sme.Err.Error())
}
