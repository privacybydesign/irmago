package irma

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/common"

	"github.com/go-errors/errors"
)

var DefaultSchemes = [2]SchemePointer{
	{
		URL:  "https://privacybydesign.foundation/schememanager/irma-demo",
		Type: SchemeTypeIssuer,
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHVnmAY+kGkFZn7XXozdI4HY8GOjm
54ngh4chTfn6WsTCf2w5rprfIqML61z2VTE4k8yJ0Z1QbyW6cdaao8obTQ==
-----END PUBLIC KEY-----`),
	},
	{
		URL:  "https://privacybydesign.foundation/schememanager/pbdf",
		Type: SchemeTypeIssuer,
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

	scheme interface {
		id() string
		idx() SchemeManagerIndex
		setIdx(idx SchemeManagerIndex)
		url() string
		timestamp() Timestamp
		setTimestamp(t Timestamp)
		setStatus(status SchemeManagerStatus)
		parseContents(conf *Configuration) error
		validate(conf *Configuration, dir string) (error, SchemeManagerStatus)
		handleUpdateFile(conf *Configuration, path string, bts []byte, transport *HTTPTransport, _ *IrmaIdentifierSet) error
		delete(conf *Configuration) error
		add(conf *Configuration)
		addError(conf *Configuration, err error)
		deleteError(conf *Configuration, err error)
		typ() SchemeType
		unmarshal([]byte, interface{}) error
		filename() string
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

const (
	SchemeManagerStatusValid               = SchemeManagerStatus("Valid")
	SchemeManagerStatusUnprocessed         = SchemeManagerStatus("Unprocessed")
	SchemeManagerStatusInvalidIndex        = SchemeManagerStatus("InvalidIndex")
	SchemeManagerStatusInvalidSignature    = SchemeManagerStatus("InvalidSignature")
	SchemeManagerStatusParsingError        = SchemeManagerStatus("ParsingError")
	SchemeManagerStatusContentParsingError = SchemeManagerStatus("ContentParsingError")

	SchemeTypeIssuer    = SchemeType("issuer")
	SchemeTypeRequestor = SchemeType("requestor")
)

func (conf *Configuration) DownloadDefaultSchemes() error {
	Logger.Info("downloading default schemes (may take a while)")
	for _, s := range DefaultSchemes {
		Logger.Debugf("Downloading %s scheme at %s", s.Type, s.URL)
		if err := conf.installScheme(s.URL, s.Publickey, s.Type); err != nil {
			return err
		}
	}
	Logger.Info("Finished downloading schemes")
	return nil
}

// InstallSchemeManager downloads and adds the specified scheme to this Configuration,
// provided its signature is valid against the specified key.
func (conf *Configuration) InstallSchemeManager(url string, publickey []byte) error {
	if len(publickey) == 0 {
		return errors.New("no public key specified")
	}
	return conf.installScheme(url, publickey, SchemeTypeIssuer)
}

// DangerousTOFUInstallSchemeManager downloads and adds the specified scheme to this Configuration,
// downloading and trusting its public key from the scheme's remote URL.
func (conf *Configuration) DangerousTOFUInstallSchemeManager(url string) error {
	return conf.installScheme(url, nil, SchemeTypeIssuer)
}

// InstallRequestorScheme downloads and adds the specified requestor scheme to this Configuration,
// provided its signature is valid against the specified key.
func (conf *Configuration) InstallRequestorScheme(url string, publickey []byte) error {
	if len(publickey) == 0 {
		return errors.New("no public key specified")
	}
	return conf.installScheme(url, publickey, SchemeTypeRequestor)
}

func (conf *Configuration) UpdateSchemes() error {
	updated := newIrmaIdentifierSet()
	for id := range conf.SchemeManagers {
		if err := conf.UpdateSchemeManager(id, updated); err != nil {
			return err
		}
	}
	for id := range conf.RequestorSchemes {
		if err := conf.UpdateRequestorScheme(id, updated); err != nil {
			return err
		}
	}
	if !updated.Empty() {
		return conf.ParseFolder()
	}
	return nil
}

func (conf *Configuration) AutoUpdateSchemes(interval uint) {
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
	conf.Scheduler.Every(uint64(interval)).Minutes().Do(update)
	// Run first update after a small delay
	go func() {
		<-time.NewTimer(200 * time.Millisecond).C
		update()
	}()
}

// UpdateSchemeManager syncs the stored version within the irma_configuration directory
// with the remote version at the scheme's URL, downloading and storing
// new and modified files, according to the index files of both versions.
// It stores the identifiers of new or updated credential types or issuers in the second parameter.
// Note: any newly downloaded files are not yet parsed and inserted into conf.
func (conf *Configuration) UpdateSchemeManager(id SchemeManagerIdentifier, downloaded *IrmaIdentifierSet) error {
	scheme := conf.SchemeManagers[id]
	err := conf.updateScheme(scheme, id.String(), downloaded)
	if err != nil {
		return err
	}
	return scheme.downloadDemoPrivateKeys(conf)
}

// UpdateRequestorScheme syncs the stored version within the irma_configuration directory
// with the remote version at the requestor scheme's URL, downloading and storing
// new and modified files, according to the index files of both versions.
// Note: any newly downloaded files are not yet parsed and inserted into conf.
func (conf *Configuration) UpdateRequestorScheme(id RequestorSchemeIdentifier, downloaded *IrmaIdentifierSet) error {
	return conf.updateScheme(conf.RequestorSchemes[id], id.String(), downloaded)
}

// ParseSchemeManagerFolder parses the entire tree of the specified scheme
// If err != nil then a problem occured
func (conf *Configuration) ParseSchemeManagerFolder(dir string) error {
	return conf.parseSchemeFolder(dir, SchemeTypeIssuer)
}

// ParseRequestorSchemeFolder parses the requestor scheme in the given directory, loading it if successfull
func (conf *Configuration) ParseRequestorSchemeFolder(dir string) error {
	return conf.parseSchemeFolder(dir, SchemeTypeRequestor)
}

// Unexported scheme helpers that work for all scheme types (issuer or requestor) follow.
// These deal with what schemes have in common: verifying the signature; authenticating
// contained files against the (signed) index; and downloading, (re)installing
// and updating them against the remote.
// The code that deals with the scheme contents, of which the structure differs per scheme type,
// is found further below as helpers on the scheme structs. This includes modifying the
// various maps on Configuration instances.

func (conf *Configuration) parseSchemeFolder(dir string, typ SchemeType) (serr error) {
	var (
		id     = filepath.Base(dir)
		scheme = newScheme(id, typ)
	)

	// From this point, we keep the scheme in our map even if it has an error. The user must check that
	// scheme.Status == SchemeManagerStatusValid, aka "Valid" before using any scheme for
	// anything, and handle accordingly.
	scheme.add(conf)
	defer scheme.addError(conf, serr)

	err, status := conf.parseScheme(scheme, dir)
	if err != nil {
		serr = &SchemeManagerError{Scheme: id, Err: err, Status: status}
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

func (conf *Configuration) parseScheme(scheme scheme, dir string) (error, SchemeManagerStatus) {
	// Verify signature and read scheme description
	var (
		err   error
		index SchemeManagerIndex
		id    = filepath.Base(dir)
	)
	if err = conf.verifySignature(dir); err != nil {
		return err, SchemeManagerStatusInvalidSignature
	}
	if index, err = conf.parseIndex(dir); err != nil {
		return err, SchemeManagerStatusInvalidIndex
	}
	if index.Scheme() != id {
		return errors.Errorf("cannot use index of scheme %s for scheme %s", index.Scheme(), id), SchemeManagerStatusParsingError
	}
	scheme.setIdx(index)

	var exists bool
	exists, err = conf.parseSchemeFile(scheme, filepath.Join(dir, scheme.filename()), scheme)
	if err != nil || !exists {
		return err, SchemeManagerStatusParsingError
	}
	if err, status := scheme.validate(conf, dir); err != nil {
		return err, status
	}

	var ts *Timestamp
	ts, exists, err = readTimestamp(filepath.Join(dir, "timestamp"))
	if err != nil || !exists {
		return errors.WrapPrefix(err, "Could not read scheme manager timestamp", 0), SchemeManagerStatusParsingError
	}
	scheme.setTimestamp(*ts)

	return nil, SchemeManagerStatusValid
}

func (conf *Configuration) parseSchemeFile(
	scheme scheme,
	path string,
	description interface{},
) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}

	base := filepath.Join(conf.Path, string(scheme.typ())+"_schemes")
	relativepath, err := filepath.Rel(base, path)
	if err != nil {
		return false, err
	}
	bts, found, err := conf.readSignedFile(scheme.idx(), base, relativepath)
	if !found {
		return false, errors.Errorf("File %s (%s %s) not present in scheme index", relativepath, path, base)
	}
	if err != nil {
		return true, err
	}

	return true, scheme.unmarshal(bts, description)
}

func (conf *Configuration) reinstallScheme(scheme scheme) (err error) {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}
	id := scheme.id()
	typ := scheme.typ()
	typePath := string(typ) + "_schemes"
	defer scheme.deleteError(conf, err)

	// first try remote
	if err = conf.reinstallSchemeFromRemote(scheme); err == nil {
		return nil
	}
	// didn't work, try from assets
	if _, err = conf.copyFromAssets(filepath.Join(typePath, id)); err != nil {
		return
	}
	err = conf.parseSchemeFolder(filepath.Join(conf.Path, typePath, id), typ)
	return
}

func (conf *Configuration) reinstallSchemeFromRemote(scheme scheme) error {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}
	pkbts, err := ioutil.ReadFile(filepath.Join(conf.Path, string(scheme.typ())+"_schemes", scheme.id(), "pk.pem"))
	if err != nil {
		return err
	}
	if err = scheme.delete(conf); err != nil {
		return err
	}
	return conf.installScheme(scheme.url(), pkbts, scheme.typ())
}

func (conf *Configuration) installScheme(url string, publickey []byte, typ SchemeType) error {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}
	id := urlEnd(url)
	typePath := string(typ) + "_schemes"
	if err := common.EnsureDirectoryExists(filepath.Join(conf.Path, typePath, id)); err != nil {
		return err
	}
	t := NewHTTPTransport(url, true)

	if publickey != nil {
		if err := common.SaveFile(filepath.Join(conf.Path, typePath, id, "pk.pem"), publickey); err != nil {
			return err
		}
	} else {
		if _, err := conf.downloadFile(t, filepath.Join(typePath, id), "pk.pem"); err != nil {
			return err
		}
	}

	scheme := newScheme("", typ) // the id will be set by the file unmarshaler below
	if err := downloadScheme(url, scheme); err != nil {
		return err
	}
	if scheme.id() != id {
		return errors.Errorf("scheme has id %s but expected %s", scheme.id(), id)
	}
	scheme.add(conf)
	if err := conf.updateScheme(scheme, id, nil); err != nil {
		return err
	}

	return conf.parseSchemeFolder(filepath.Join(conf.Path, typePath, id), typ)
}

func (conf *Configuration) updateScheme(scheme scheme, id string, downloaded *IrmaIdentifierSet) error {
	if conf.readOnly {
		return errors.New("cannot update a read-only configuration")
	}
	if scheme == nil {
		return errors.Errorf("Cannot update unknown scheme %s", id)
	}
	typ := string(scheme.typ())
	Logger.WithField(typ+"scheme", id).Info("checking for updates", typ)
	shouldUpdate, timestamp, index, err := conf.checkRemoteScheme(scheme)
	if err != nil {
		return err
	}
	if !shouldUpdate {
		return nil
	}

	var (
		transport = NewHTTPTransport(scheme.url(), true)
		oldIndex  = scheme.idx()
		typePath  = typ + "_schemes"
	)
	for path, newHash := range index {
		fullpath := filepath.Join(conf.Path, typePath, path)
		oldHash, known := oldIndex[path]
		var have bool
		have, err = common.PathExists(fullpath)
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
		stripped := path[len(id)+1:] // scheme URL already ends with its name
		// Download the new file, store it in our own irma_configuration folder
		var bts []byte
		if bts, err = conf.downloadSignedFile(transport, filepath.Join(typePath, id), stripped, newHash); err != nil {
			return err
		}
		// handle file contents per scheme type
		if err = scheme.handleUpdateFile(conf, path, bts, transport, downloaded); err != nil {
			return err
		}
	}

	scheme.setTimestamp(*timestamp)
	scheme.setIdx(index)
	return nil
}

func (conf *Configuration) checkRemoteScheme(scheme scheme) (bool, *Timestamp, SchemeManagerIndex, error) {
	timestamp, indexbts, sigbts, index, err := conf.checkRemoteTimestamp(scheme)
	if err != nil {
		return false, nil, nil, err
	}
	id := scheme.id()
	typ := string(scheme.typ())
	timestampdiff := int64(timestamp.Sub(scheme.timestamp()))
	if timestampdiff == 0 {
		Logger.WithField(typ+"scheme", id).Info("scheme is up-to-date, not updating")
		return false, nil, index, nil
	} else if timestampdiff < 0 {
		Logger.WithField(typ+"scheme", id).Info("local scheme is newer than remote, not updating")
		return false, nil, index, nil
	}
	// timestampdiff > 0
	Logger.WithField(typ+"scheme", id).Info("scheme is outdated, updating")

	// save the index and its signature against which we authenticated the timestamp
	// for future use: as they are themselves not in the index, the loop below doesn't touch them
	if err = conf.writeIndex(filepath.Join(conf.Path, typ+"_schemes", id), indexbts, sigbts); err != nil {
		return false, nil, nil, err
	}

	return true, timestamp, index, nil
}

func (conf *Configuration) checkRemoteTimestamp(scheme scheme) (
	*Timestamp, []byte, []byte, SchemeManagerIndex, error,
) {
	t := NewHTTPTransport(scheme.url(), true)
	indexbts, err := t.GetBytes("index")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sig, err := t.GetBytes("index.sig")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	timestampbts, err := t.GetBytes("timestamp")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pk, err := conf.schemePublicKey(filepath.Join(conf.Path, string(scheme.typ())+"_schemes", scheme.id()))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Verify signature and the timestamp hash in the index
	if err = signed.Verify(pk, indexbts, sig); err != nil {
		return nil, nil, nil, nil, err
	}
	index := SchemeManagerIndex(make(map[string]SchemeFileHash))
	if err = index.FromString(string(indexbts)); err != nil {
		return nil, nil, nil, nil, err
	}
	sha := sha256.Sum256(timestampbts)
	if !bytes.Equal(index[scheme.id()+"/timestamp"], sha[:]) {
		return nil, nil, nil, nil, errors.Errorf("signature over timestamp is not valid")
	}

	timestamp, err := parseTimestamp(timestampbts)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return timestamp, indexbts, sig, index, nil
}

func (conf *Configuration) writeIndex(dest string, indexbts, sigbts []byte) error {
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
	if err != nil || !exists {
		return true, errors.WrapPrefix(err, "Could not read asset timestamp of scheme "+subdir, 0)
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
	indexbts, err := ioutil.ReadFile(filepath.Join(dir, "index"))
	if err != nil {
		return err
	}

	// Read and parse scheme public key
	pk, err := conf.schemePublicKey(dir)
	if err != nil {
		return err
	}

	// Read and parse signature
	sig, err := ioutil.ReadFile(filepath.Join(dir, "index.sig"))
	if err != nil {
		return err
	}

	return signed.Verify(pk, indexbts, sig)
}

func (conf *Configuration) schemePublicKey(dir string) (*ecdsa.PublicKey, error) {
	pkbts, err := ioutil.ReadFile(filepath.Join(dir, "pk.pem"))
	if err != nil {
		return nil, err
	}
	return signed.UnmarshalPemPublicKey(pkbts)
}

func (conf *Configuration) downloadSignedFile(
	transport *HTTPTransport, scheme, path string, hash SchemeFileHash,
) ([]byte, error) {
	b, err := transport.GetBytes(path)
	if err != nil {
		return nil, err
	}
	sha := sha256.Sum256(b)
	if hash != nil && !bytes.Equal(hash, sha[:]) {
		return nil, errors.Errorf("Signature over new file %s is not valid", path)
	}
	dest := filepath.Join(conf.Path, scheme, filepath.FromSlash(path))
	if err = common.EnsureDirectoryExists(filepath.Dir(dest)); err != nil {
		return nil, err
	}
	return b, common.SaveFile(dest, b)
}

func (conf *Configuration) downloadFile(transport *HTTPTransport, scheme string, path string) ([]byte, error) {
	return conf.downloadSignedFile(transport, scheme, path, nil)
}

// readSignedFile reads the file at the specified path
// and verifies its authenticity by checking that the file hash
// is present in the (signed) scheme index file.
func (conf *Configuration) readSignedFile(index SchemeManagerIndex, base string, path string) ([]byte, bool, error) {
	signedHash, ok := index[filepath.ToSlash(path)]
	if !ok {
		return nil, false, nil
	}

	bts, err := conf.readHashedFile(filepath.Join(base, path), signedHash)
	return bts, true, err
}

func (conf *Configuration) readHashedFile(path string, hash SchemeFileHash) ([]byte, error) {
	bts, err := ioutil.ReadFile(path)
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
func (conf *Configuration) parseIndex(dir string) (SchemeManagerIndex, error) {
	path := filepath.Join(dir, "index")
	if err := common.AssertPathExists(path); err != nil {
		return nil, fmt.Errorf("missing scheme manager index file; tried %s", path)
	}
	indexbts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	index := SchemeManagerIndex(make(map[string]SchemeFileHash))
	if err = index.FromString(string(indexbts)); err != nil {
		return nil, err
	}

	return index, conf.checkUnsignedFiles(dir, index)
}

func (conf *Configuration) checkUnsignedFiles(dir string, index SchemeManagerIndex) error {
	return common.WalkDir(dir, func(path string, info os.FileInfo) error {
		relpath, err := filepath.Rel(filepath.Dir(dir), path)
		if err != nil {
			return err
		}
		for _, ex := range sigExceptions {
			if ex.MatchString(filepath.ToSlash(relpath)) {
				return nil
			}
		}

		if info.IsDir() {
			if !dirInScheme(index, relpath) {
				conf.Warnings = append(conf.Warnings, "Ignored dir: "+relpath)
			}
		} else {
			if _, ok := index[relpath]; !ok {
				conf.Warnings = append(conf.Warnings, "Ignored file: "+relpath)
			}
		}

		return nil
	})
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
		regexp.MustCompile(`\.DS_Store$`),
	}

	issPattern  = regexp.MustCompile("^([^/]+)/([^/]+)/description\\.xml")
	credPattern = regexp.MustCompile("^([^/]+)/([^/]+)/Issues/([^/]+)/description\\.xml")
	keyPattern  = regexp.MustCompile("^([^/]+)/([^/]+)/PublicKeys/(\\d+)\\.xml")
)

func dirInScheme(index SchemeManagerIndex, dir string) bool {
	for indexpath := range index {
		if strings.HasPrefix(indexpath, dir) {
			return true
		}
	}
	return false
}

func downloadScheme(url string, scheme scheme) error {
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	filename := scheme.filename()
	if strings.HasSuffix(url, "/"+filename) {
		url = url[:len(url)-1-len(filename)]
	}
	b, err := NewHTTPTransport(url, true).GetBytes(filename)
	if err != nil {
		return err
	}
	if err = scheme.unmarshal(b, scheme); err != nil {
		return err
	}
	return nil
}

func newScheme(id string, typ SchemeType) scheme {
	switch typ {
	case SchemeTypeIssuer:
		return &SchemeManager{Status: SchemeManagerStatusUnprocessed, ID: id}
	case SchemeTypeRequestor:
		return &RequestorScheme{Status: SchemeManagerStatusUnprocessed, ID: NewRequestorSchemeIdentifier(id)}
	default:
		panic("newScheme() does not support scheme type " + typ)
	}
}

func urlEnd(url string) string {
	i := strings.LastIndexByte(url, '/')
	return url[i+1:]
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

func (scheme *SchemeManager) parseContents(conf *Configuration) error {
	path := filepath.Join(conf.Path, "issuer_schemes", scheme.ID)
	return common.IterateSubfolders(path, func(dir string, _ os.FileInfo) error {
		issuer := &Issuer{}

		exists, err := conf.parseSchemeFile(scheme, filepath.Join(dir, "description.xml"), issuer)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if issuer.XMLVersion < 4 {
			return errors.New("Unsupported issuer description")
		}

		if err = conf.validateIssuer(scheme, issuer, dir); err != nil {
			return err
		}

		conf.Issuers[issuer.Identifier()] = issuer
		return scheme.parseCredentialsFolder(conf, issuer, filepath.Join(dir, "Issues"))
	})
}

func (scheme *SchemeManager) validate(conf *Configuration, dir string) (error, SchemeManagerStatus) {
	if filepath.Base(dir) != scheme.ID {
		return errors.Errorf("Scheme %s has wrong directory name %s", scheme.ID, filepath.Base(dir)), SchemeManagerStatusParsingError
	}
	if scheme.XMLVersion < 7 {
		return errors.New("Unsupported scheme manager description"), SchemeManagerStatusParsingError
	}
	if scheme.KeyshareServer != "" {
		if err := common.AssertPathExists(filepath.Join(dir, "kss-0.pem")); err != nil {
			return errors.Errorf("Scheme %s has keyshare URL but no keyshare public key kss-0.pem", scheme.ID), SchemeManagerStatusParsingError
		}
	}
	conf.validateTranslations(fmt.Sprintf("Scheme %s", scheme.ID), scheme)

	// Verify that all other files are validly signed
	if err := scheme.verifyFiles(conf); err != nil {
		return err, SchemeManagerStatusInvalidSignature
	}

	return nil, SchemeManagerStatusValid
}

func (scheme *SchemeManager) handleUpdateFile(conf *Configuration, filename string, _ []byte, _ *HTTPTransport, downloaded *IrmaIdentifierSet) error {
	// See if the file is a credential type or issuer, and add it to the downloaded set if so
	if downloaded == nil {
		return nil
	}
	var matches []string
	matches = issPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 3 {
		issid := NewIssuerIdentifier(fmt.Sprintf("%s.%s", matches[1], matches[2]))
		downloaded.Issuers[issid] = struct{}{}
	}
	matches = credPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 4 {
		credid := NewCredentialTypeIdentifier(fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3]))
		downloaded.CredentialTypes[credid] = struct{}{}
	}
	matches = keyPattern.FindStringSubmatch(filepath.ToSlash(filename))
	if len(matches) == 4 {
		issid := NewIssuerIdentifier(fmt.Sprintf("%s.%s", matches[1], matches[2]))
		counter, err := strconv.ParseUint(matches[3], 10, 32)
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
	for iss := range conf.publicKeys {
		if iss.Root() == name {
			delete(conf.publicKeys, iss)
		}
	}
	for cred := range conf.CredentialTypes {
		if cred.Root() == name {
			delete(conf.CredentialTypes, cred)
		}
	}

	return os.RemoveAll(filepath.Join(conf.Path, "issuer_schemes", id.Name()))
}

func (scheme *SchemeManager) add(conf *Configuration) {
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

func (_ *SchemeManager) typ() SchemeType { return SchemeTypeIssuer }

func (_ *SchemeManager) unmarshal(bts []byte, dest interface{}) error {
	return xml.Unmarshal(bts, dest)
}

func (_ *SchemeManager) filename() string { return "description.xml" }

func (scheme *SchemeManager) verifyFiles(conf *Configuration) error {
	var (
		exists bool
		err    error
		dir    = filepath.Join(conf.Path, "issuer_schemes")
	)
	for file := range scheme.index {
		exists, err = common.PathExists(filepath.Join(dir, file))
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		// Don't care about the actual bytes
		if _, _, err = conf.readSignedFile(scheme.index, dir, file); err != nil {
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
		exists, err := conf.parseSchemeFile(scheme, filepath.Join(dir, "description.xml"), cred)
		if err != nil {
			return err
		}
		if !exists {
			return nil
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
		for index, attr := range cred.AttributeTypes {
			attr.Index = index
			attr.SchemeManagerID = cred.SchemeManagerID
			attr.IssuerID = cred.IssuerID
			attr.CredentialTypeID = cred.ID
			conf.AttributeTypes[attr.GetAttributeTypeIdentifier()] = attr
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
func (scheme *SchemeManager) downloadDemoPrivateKeys(conf *Configuration) error {
	if !scheme.Demo {
		return nil
	}

	Logger.Debugf("Attempting downloading of private keys of scheme %s", scheme.ID)
	transport := NewHTTPTransport(scheme.URL, true)

	_, err := conf.downloadFile(transport, filepath.Join("issuer_schemes", scheme.ID), "sk.pem")
	if err != nil { // If downloading of any of the private key fails just log it, and then continue
		Logger.Warnf("Downloading private key of scheme %s failed ", scheme.ID)
	}

	pkpath := fmt.Sprintf(pubkeyPattern, conf.Path, scheme.ID, "*")
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return err
	}

	// For each public key, attempt to download a corresponding private key
	for _, file := range files {
		i := strings.LastIndex(pkpath, "PublicKeys")
		skpath := file[:i] + strings.Replace(file[i:], "PublicKeys", "PrivateKeys", 1)
		parts := strings.Split(skpath, "/")
		exists, err := common.PathExists(filepath.FromSlash(skpath))
		if exists || err != nil {
			continue
		}
		remote := strings.Join(parts[len(parts)-3:], "/")
		if _, err = conf.downloadFile(transport, filepath.Join("issuer_schemes", scheme.ID), remote); err != nil {
			Logger.Warnf("Downloading private key %s failed: %s", skpath, err)
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

func (scheme *RequestorScheme) parseContents(conf *Configuration) error {
	scheme.purge(conf)
	for _, requestor := range scheme.requestors {
		for _, hostname := range requestor.Hostnames {
			if _, ok := conf.Requestors[hostname]; ok {
				return errors.Errorf("Double occurence of hostname %s", hostname)
			}
			conf.Requestors[hostname] = requestor
		}
	}
	return nil
}

func (scheme *RequestorScheme) validate(conf *Configuration, dir string) (error, SchemeManagerStatus) {
	if filepath.Base(dir) != scheme.id() {
		return errors.Errorf("Scheme %s has wrong directory name %s", scheme.ID, filepath.Base(dir)), SchemeManagerStatusParsingError
	}
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
		path := filepath.Join(conf.Path, "requestor_schemes", file)
		exists, err = conf.parseSchemeFile(scheme, path, &currentChunk)
		if !exists && err != nil {
			return errors.Errorf("file %s of requestor scheme %s in index but not found on disk", file, scheme.ID), SchemeManagerStatusParsingError
		}
		for _, v := range currentChunk {
			if v.Scheme != scheme.ID {
				return errors.Errorf("Requestor %s has incorrect scheme %s", v.Name, v.Scheme), SchemeManagerStatusParsingError

			}
		}
		requestors = append(requestors, currentChunk...)
	}

	// Verify all referenced logos
	for _, requestor := range requestors {
		if requestor.Logo == nil {
			continue
		}
		var hash []byte
		hash, err = hex.DecodeString(*requestor.Logo)
		if err != nil {
			return err, SchemeManagerStatusParsingError
		}
		if _, err = conf.readHashedFile(filepath.Join(dir, "assets", *requestor.Logo+".png"), hash); err != nil {
			return err, SchemeManagerStatusInvalidSignature
		}
	}
	scheme.requestors = requestors
	return nil, SchemeManagerStatusValid
}

func (scheme *RequestorScheme) handleUpdateFile(conf *Configuration, path string, bts []byte, transport *HTTPTransport, downloaded *IrmaIdentifierSet) error {
	// Download logos if needed
	if filepath.Base(path) == "description.json" || filepath.Base(path) == "timestamp" {
		return nil
	}
	var (
		data RequestorChunk
		err  error
		id   = scheme.id()
	)
	if err = json.Unmarshal(bts, &data); err != nil {
		return err
	}
	for _, requestor := range data {
		if requestor.Logo == nil {
			continue
		}
		var ok bool
		ok, err = common.PathExists(filepath.Join(conf.Path, "requestor_schemes", id, "assets", *requestor.Logo+".png"))
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
		if _, err = conf.downloadSignedFile(transport, filepath.Join("requestor_schemes", id), filepath.Join("assets", *requestor.Logo+".png"), hash); err != nil {
			return err
		}
	}
	downloaded.RequestorSchemes[scheme.ID] = struct{}{}
	return nil
}

func (scheme *RequestorScheme) delete(conf *Configuration) error {
	if conf.readOnly {
		return errors.New("cannot delete scheme from a read-only configuration")
	}
	scheme.purge(conf)

	return os.RemoveAll(filepath.Join(conf.Path, "requestor_schemes", scheme.ID.Name()))
}

func (scheme *RequestorScheme) add(conf *Configuration) {
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

func (_ *RequestorScheme) typ() SchemeType { return SchemeTypeRequestor }

func (_ *RequestorScheme) unmarshal(bts []byte, dest interface{}) error {
	return json.Unmarshal(bts, dest)
}

func (_ *RequestorScheme) filename() string { return "description.json" }

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
