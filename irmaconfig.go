package irma

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"crypto/sha256"

	"fmt"

	"strings"

	"sort"

	"bytes"

	"encoding/hex"

	"crypto/x509"
	"encoding/pem"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/sirupsen/logrus"
)

// Configuration keeps track of scheme managers, issuers, credential types and public keys,
// dezerializing them from an irma_configuration folder, and downloads and saves new ones on demand.
type Configuration struct {
	SchemeManagers  map[SchemeManagerIdentifier]*SchemeManager
	Issuers         map[IssuerIdentifier]*Issuer
	CredentialTypes map[CredentialTypeIdentifier]*CredentialType
	AttributeTypes  map[AttributeTypeIdentifier]*AttributeType

	// Issuer private keys. If set (after calling ParseFolder()), will use these keys
	// instead of keys in irma_configuration/$issuer/PrivateKeys.
	PrivateKeys map[IssuerIdentifier]map[uint]*gabi.PrivateKey

	Revocation *RevocationStorage `json:"-"`

	Scheduler *gocron.Scheduler

	// Path to the irma_configuration folder that this instance represents
	Path string

	// DisabledSchemeManagers keeps track of scheme managers that did not parse  succesfully
	// (i.e., invalid signature, parsing error), and the problem that occurred when parsing them
	DisabledSchemeManagers map[SchemeManagerIdentifier]*SchemeManagerError

	Warnings []string

	kssPublicKeys map[SchemeManagerIdentifier]map[int]*rsa.PublicKey
	publicKeys    map[IssuerIdentifier]map[uint]*gabi.PublicKey
	reverseHashes map[string]CredentialTypeIdentifier
	initialized   bool
	assets        string
	readOnly      bool

	options ConfigurationOptions
}

// ConfigurationFileHash encodes the SHA256 hash of an authenticated
// file under a scheme manager within the configuration folder.
type ConfigurationFileHash []byte

// SchemeManagerIndex is a (signed) list of files under a scheme manager
// along with their SHA266 hash
type SchemeManagerIndex map[string]ConfigurationFileHash

type SchemeManagerStatus string

type SchemeManagerError struct {
	Manager SchemeManagerIdentifier
	Status  SchemeManagerStatus
	Err     error
}

type UnknownIdentifierError struct {
	ErrorType
	Missing *IrmaIdentifierSet
}

type RequiredAttributeMissingError struct {
	ErrorType
	Missing *IrmaIdentifierSet
}

const (
	SchemeManagerStatusValid               = SchemeManagerStatus("Valid")
	SchemeManagerStatusUnprocessed         = SchemeManagerStatus("Unprocessed")
	SchemeManagerStatusInvalidIndex        = SchemeManagerStatus("InvalidIndex")
	SchemeManagerStatusInvalidSignature    = SchemeManagerStatus("InvalidSignature")
	SchemeManagerStatusParsingError        = SchemeManagerStatus("ParsingError")
	SchemeManagerStatusContentParsingError = SchemeManagerStatus("ContentParsingError")

	pubkeyPattern  = "%s/%s/%s/PublicKeys/*.xml"
	privkeyPattern = "%s/%s/%s/PrivateKeys/*.xml"
)

var (
	validLangs = []string{"en", "nl"} // Hardcode these for now, TODO make configurable
)

func (sme SchemeManagerError) Error() string {
	return fmt.Sprintf("Error parsing scheme manager %s: %s", sme.Manager.Name(), sme.Err.Error())
}

type ConfigurationOptions struct {
	Assets              string
	ReadOnly            bool
	RevocationDBConnStr string
	RevocationDBType    string
	RevocationSettings  map[CredentialTypeIdentifier]*RevocationSetting
}

// NewConfiguration returns a new configuration. After this
// ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string, opts ConfigurationOptions) (conf *Configuration, err error) {
	conf = &Configuration{
		Path:     path,
		assets:   opts.Assets,
		readOnly: opts.ReadOnly,
		options:  opts,
	}

	if conf.assets != "" { // If an assets folder is specified, then it must exist
		if err = fs.AssertPathExists(conf.assets); err != nil {
			return nil, errors.WrapPrefix(err, "Nonexistent assets folder specified", 0)
		}
	}
	if err = fs.EnsureDirectoryExists(conf.Path); err != nil {
		return nil, err
	}

	// Init all maps
	conf.clear()

	return
}

func (conf *Configuration) clear() {
	conf.SchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManager)
	conf.Issuers = make(map[IssuerIdentifier]*Issuer)
	conf.CredentialTypes = make(map[CredentialTypeIdentifier]*CredentialType)
	conf.AttributeTypes = make(map[AttributeTypeIdentifier]*AttributeType)
	conf.DisabledSchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManagerError)
	conf.kssPublicKeys = make(map[SchemeManagerIdentifier]map[int]*rsa.PublicKey)
	conf.publicKeys = make(map[IssuerIdentifier]map[uint]*gabi.PublicKey)
	conf.PrivateKeys = make(map[IssuerIdentifier]map[uint]*gabi.PrivateKey)
	conf.reverseHashes = make(map[string]CredentialTypeIdentifier)
}

// ParseFolder populates the current Configuration by parsing the storage path,
// listing the containing scheme managers, issuers and credential types.
func (conf *Configuration) ParseFolder() (err error) {
	// Init all maps
	conf.clear()

	// Copy any new or updated scheme managers out of the assets into storage
	if conf.assets != "" {
		err = fs.IterateSubfolders(conf.assets, func(dir string, _ os.FileInfo) error {
			scheme := NewSchemeManagerIdentifier(filepath.Base(dir))
			uptodate, err := conf.isUpToDate(scheme)
			if err != nil {
				return err
			}
			if !uptodate {
				_, err = conf.CopyManagerFromAssets(scheme)
			}
			return err
		})
		if err != nil {
			return err
		}
	}

	// Parse scheme managers in storage
	var mgrerr *SchemeManagerError
	err = fs.IterateSubfolders(conf.Path, func(dir string, _ os.FileInfo) error {
		manager := NewSchemeManager(filepath.Base(dir))
		err := conf.ParseSchemeManagerFolder(dir, manager)
		if err == nil {
			return nil // OK, do next scheme manager folder
		}
		// If there is an error, and it is of type SchemeManagerError, return nil
		// so as to continue parsing other managers.
		var ok bool
		if mgrerr, ok = err.(*SchemeManagerError); ok {
			conf.DisabledSchemeManagers[manager.Identifier()] = mgrerr
			return nil
		}
		return err // Not a SchemeManagerError? return it & halt parsing now
	})
	if err != nil {
		return
	}

	if conf.Revocation == nil {
		conf.Scheduler = gocron.NewScheduler()
		conf.Scheduler.Start()
		conf.Revocation = &RevocationStorage{conf: conf}
		if err = conf.Revocation.Load(
			Logger.IsLevelEnabled(logrus.DebugLevel),
			conf.options.RevocationDBType,
			conf.options.RevocationDBConnStr,
			conf.options.RevocationSettings,
		); err != nil {
			return err
		}
	}

	conf.initialized = true
	if mgrerr != nil {
		return mgrerr
	}
	return
}

// ParseOrRestoreFolder parses the irma_configuration folder, and when possible attempts to restore
// any broken scheme managers from their remote.
// Any error encountered during parsing is considered recoverable only if it is of type *SchemeManagerError;
// In this case the scheme in which it occured is downloaded from its remote and re-parsed.
// If any other error is encountered at any time, it is returned immediately.
// If no error is returned, parsing and possibly restoring has been succesfull, and there should be no
// disabled scheme managers.
func (conf *Configuration) ParseOrRestoreFolder() error {
	err := conf.ParseFolder()
	// Only in case of a *SchemeManagerError might we be able to recover
	if _, isSchemeMgrErr := err.(*SchemeManagerError); !isSchemeMgrErr {
		return err
	}
	if err != nil && (conf.assets == "" || conf.readOnly) {
		return err
	}

	for id := range conf.DisabledSchemeManagers {
		if err = conf.ReinstallSchemeManager(conf.SchemeManagers[id]); err == nil {
			continue
		}
		if _, err = conf.CopyManagerFromAssets(id); err != nil {
			return err // File system error, too serious, bail out now
		}
		name := id.String()
		if err = conf.ParseSchemeManagerFolder(filepath.Join(conf.Path, name), NewSchemeManager(name)); err == nil {
			delete(conf.DisabledSchemeManagers, id)
		}
	}

	return err
}

// ParseSchemeManagerFolder parses the entire tree of the specified scheme manager
// If err != nil then a problem occured
func (conf *Configuration) ParseSchemeManagerFolder(dir string, manager *SchemeManager) (err error) {
	// From this point, keep it in our map even if it has an error. The user must check either:
	// - manager.Status == SchemeManagerStatusValid, aka "VALID"
	// - or equivalently, manager.Valid == true
	// before using any scheme manager for anything, and handle accordingly
	conf.SchemeManagers[manager.Identifier()] = manager

	// Ensure we return a SchemeManagerError when any error occurs
	defer func() {
		if err != nil {
			err = &SchemeManagerError{
				Manager: manager.Identifier(),
				Err:     err,
				Status:  manager.Status,
			}
		}
	}()

	// Verify signature and read scheme manager description
	if err = conf.VerifySignature(manager.Identifier()); err != nil {
		return
	}
	if manager.index, err = conf.parseIndex(filepath.Base(dir), manager); err != nil {
		manager.Status = SchemeManagerStatusInvalidIndex
		return
	}
	exists, err := conf.pathToDescription(manager, dir+"/description.xml", manager)
	if err != nil {
		manager.Status = SchemeManagerStatusParsingError
		return
	}
	if !exists {
		manager.Status = SchemeManagerStatusParsingError
		return errors.New("Scheme manager description not found")
	}
	if err = conf.validateScheme(manager, dir); err != nil {
		return
	}

	// Verify that all other files are validly signed
	err = conf.VerifySchemeManager(manager)
	if err != nil {
		manager.Status = SchemeManagerStatusInvalidSignature
		return
	}

	// Read timestamp indicating time of last modification
	ts, exists, err := readTimestamp(dir + "/timestamp")
	if err != nil || !exists {
		return errors.WrapPrefix(err, "Could not read scheme manager timestamp", 0)
	}
	manager.Timestamp = *ts

	// Parse contained issuers and credential types
	err = conf.parseIssuerFolders(manager, dir)
	if err != nil {
		manager.Status = SchemeManagerStatusContentParsingError
		return
	}
	manager.Status = SchemeManagerStatusValid
	manager.Valid = true
	return
}

// PrivateKey returns the specified private key of the specified issuer if present; an error otherwise.
func (conf *Configuration) PrivateKey(id IssuerIdentifier, counter uint) (*gabi.PrivateKey, error) {
	if _, haveIssuer := conf.PrivateKeys[id]; haveIssuer {
		if sk := conf.PrivateKeys[id][counter]; sk != nil {
			return sk, nil
		}
	}

	path := fmt.Sprintf(privkeyPattern, conf.Path, id.SchemeManagerIdentifier().Name(), id.Name())
	file := strings.Replace(path, "*", strconv.FormatUint(uint64(counter), 10), 1)
	sk, err := gabi.NewPrivateKeyFromFile(file)
	if err != nil {
		return nil, err
	}
	if sk.Counter != counter {
		return nil, errors.Errorf("Private key %s of issuer %s has wrong <Counter>", file, id.String())
	}

	if conf.PrivateKeys[id] == nil {
		conf.PrivateKeys[id] = make(map[uint]*gabi.PrivateKey)
	}
	conf.PrivateKeys[id][counter] = sk

	return sk, nil
}

// PrivateKeyLatest returns the latest private key of the specified issuer.
func (conf *Configuration) PrivateKeyLatest(id IssuerIdentifier) (*gabi.PrivateKey, error) {
	indices, err := conf.PrivateKeyIndices(id)
	if err != nil {
		return nil, err
	}
	if len(indices) == 0 {
		return nil, errors.New("no private keys found")
	}
	return conf.PrivateKey(id, indices[len(indices)-1])
}

// PublicKey returns the specified public key, or nil if not present in the Configuration.
func (conf *Configuration) PublicKey(id IssuerIdentifier, counter uint) (*gabi.PublicKey, error) {
	var haveIssuer, haveKey bool
	var err error
	_, haveIssuer = conf.publicKeys[id]
	if haveIssuer {
		_, haveKey = conf.publicKeys[id][counter]
	}

	// If we have not seen this issuer or key before in conf.publicKeys,
	// try to parse the public key folder; new keys might have been put there since we last parsed it
	if !haveIssuer || !haveKey {
		if err = conf.parseKeysFolder(id); err != nil {
			return nil, err
		}
	}
	return conf.publicKeys[id][counter], nil
}

// PublicKeyLatest returns the latest private key of the specified issuer.
func (conf *Configuration) PublicKeyLatest(id IssuerIdentifier) (*gabi.PublicKey, error) {
	indices, err := conf.PublicKeyIndices(id)
	if err != nil {
		return nil, err
	}
	if len(indices) == 0 {
		return nil, errors.New("no public keys found")
	}
	return conf.PublicKey(id, indices[len(indices)-1])
}

// KeyshareServerKeyFunc returns a function that returns the public key with which to verify a keyshare server JWT,
// suitable for passing to jwt.Parse() and jwt.ParseWithClaims().
func (conf *Configuration) KeyshareServerKeyFunc(scheme SchemeManagerIdentifier) func(t *jwt.Token) (interface{}, error) {
	return func(t *jwt.Token) (i interface{}, e error) {
		var kid int
		if kidstr, ok := t.Header["kid"].(string); ok {
			var err error
			if kid, err = strconv.Atoi(kidstr); err != nil {
				return nil, err
			}
		}
		return conf.KeyshareServerPublicKey(scheme, kid)
	}
}

// KeyshareServerPublicKey returns the i'th public key of the specified scheme.
func (conf *Configuration) KeyshareServerPublicKey(scheme SchemeManagerIdentifier, i int) (*rsa.PublicKey, error) {
	if _, contains := conf.kssPublicKeys[scheme]; !contains {
		conf.kssPublicKeys[scheme] = make(map[int]*rsa.PublicKey)
	}
	if _, contains := conf.kssPublicKeys[scheme][i]; !contains {
		pkbts, err := ioutil.ReadFile(filepath.Join(conf.Path, scheme.Name(), fmt.Sprintf("kss-%d.pem", i)))
		if err != nil {
			return nil, err
		}
		pkblk, _ := pem.Decode(pkbts)
		genericPk, err := x509.ParsePKIXPublicKey(pkblk.Bytes)
		if err != nil {
			return nil, err
		}
		pk, ok := genericPk.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("Invalid keyshare server public key")
		}
		conf.kssPublicKeys[scheme][i] = pk
	}
	return conf.kssPublicKeys[scheme][i], nil
}

func (conf *Configuration) addReverseHash(credid CredentialTypeIdentifier) {
	hash := sha256.Sum256([]byte(credid.String()))
	conf.reverseHashes[base64.StdEncoding.EncodeToString(hash[:16])] = credid
}

func (conf *Configuration) hashToCredentialType(hash []byte) *CredentialType {
	if str, exists := conf.reverseHashes[base64.StdEncoding.EncodeToString(hash)]; exists {
		return conf.CredentialTypes[str]
	}
	return nil
}

// IsInitialized indicates whether this instance has successfully been initialized.
func (conf *Configuration) IsInitialized() bool {
	return conf.initialized
}

// Prune removes any invalid scheme managers and everything they own from this Configuration
func (conf *Configuration) Prune() {
	for _, manager := range conf.SchemeManagers {
		if !manager.Valid {
			_ = conf.RemoveSchemeManager(manager.Identifier(), false) // does not return errors
		}
	}
}

func (conf *Configuration) parseIssuerFolders(manager *SchemeManager, path string) error {
	return fs.IterateSubfolders(path, func(dir string, _ os.FileInfo) error {
		issuer := &Issuer{}
		exists, err := conf.pathToDescription(manager, dir+"/description.xml", issuer)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if issuer.XMLVersion < 4 {
			return errors.New("Unsupported issuer description")
		}

		if err = conf.validateIssuer(manager, issuer, dir); err != nil {
			return err
		}

		conf.Issuers[issuer.Identifier()] = issuer
		issuer.Valid = conf.SchemeManagers[issuer.SchemeManagerIdentifier()].Valid
		return conf.parseCredentialsFolder(manager, issuer, dir+"/Issues/")
	})
}

func (conf *Configuration) DeleteSchemeManager(id SchemeManagerIdentifier) error {
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
	if !conf.readOnly {
		return os.RemoveAll(filepath.Join(conf.Path, id.Name()))
	}
	return nil
}

// parse $schememanager/$issuer/PublicKeys/$i.xml for $i = 1, ...
func (conf *Configuration) parseKeysFolder(issuerid IssuerIdentifier) error {
	manager := conf.SchemeManagers[issuerid.SchemeManagerIdentifier()]
	conf.publicKeys[issuerid] = map[uint]*gabi.PublicKey{}
	path := fmt.Sprintf(pubkeyPattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(path)
	if err != nil {
		return err
	}

	for _, file := range files {
		filename := filepath.Base(file)
		count := filename[:len(filename)-4]
		i, err := strconv.ParseUint(count, 10, 32)
		if err != nil {
			return err
		}
		relativepath, err := filepath.Rel(conf.Path, file)
		if err != nil {
			return err
		}
		bts, found, err := conf.ReadAuthenticatedFile(manager, relativepath)
		if err != nil || !found {
			return err
		}
		pk, err := gabi.NewPublicKeyFromBytes(bts)
		if err != nil {
			return err
		}
		if pk.Counter != uint(i) {
			return errors.Errorf("Public key %s of issuer %s has wrong <Counter>", file, issuerid.String())
		}
		pk.Issuer = issuerid.String()
		conf.publicKeys[issuerid][uint(i)] = pk
	}

	return nil
}

func sorter(ints []uint) func(i, j int) bool {
	return func(i, j int) bool { return ints[i] < ints[j] }
}

// unionset returns the concatenation of a and b, without duplicates, and sorted.
func unionset(a, b []uint) []uint {
	m := map[uint]struct{}{}
	for _, c := range [][]uint{a, b} {
		for _, i := range c {
			m[i] = struct{}{}
		}
	}
	var ints []uint
	for i := range m {
		ints = append(ints, i)
	}
	sort.Slice(ints, sorter(ints))
	return ints
}

func (conf *Configuration) PrivateKeyIndices(issuerid IssuerIdentifier) (i []uint, err error) {
	filekeys, err := conf.matchKeyPattern(issuerid, privkeyPattern)
	if err != nil {
		return nil, err
	}
	var mapkeys []uint
	for _, sk := range conf.PrivateKeys[issuerid] {
		mapkeys = append(mapkeys, sk.Counter)
	}
	return unionset(filekeys, mapkeys), nil
}

func (conf *Configuration) PublicKeyIndices(issuerid IssuerIdentifier) (i []uint, err error) {
	return conf.matchKeyPattern(issuerid, pubkeyPattern)
}

func (conf *Configuration) matchKeyPattern(issuerid IssuerIdentifier, pattern string) (ints []uint, err error) {
	pkpath := fmt.Sprintf(pattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return
	}
	for _, file := range files {
		var count uint64
		base := filepath.Base(file)
		if count, err = strconv.ParseUint(base[:len(base)-4], 10, 32); err != nil {
			return
		}
		ints = append(ints, uint(count))
	}
	sort.Slice(ints, sorter(ints))
	return
}

// parse $schememanager/$issuer/Issues/*/description.xml
func (conf *Configuration) parseCredentialsFolder(manager *SchemeManager, issuer *Issuer, path string) error {
	var foundcred bool
	err := fs.IterateSubfolders(path, func(dir string, _ os.FileInfo) error {
		cred := &CredentialType{}
		exists, err := conf.pathToDescription(manager, dir+"/description.xml", cred)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err = conf.validateCredentialType(manager, issuer, cred, dir); err != nil {
			return err
		}
		foundcred = true
		if cred.RevocationUpdateCount == 0 {
			cred.RevocationUpdateCount = RevocationParameters.DefaultUpdateEventCount
		}
		if cred.RevocationUpdateSpeed == 0 {
			cred.RevocationUpdateSpeed = RevocationParameters.ClientDefaultUpdateSpeed
		}
		cred.Valid = conf.SchemeManagers[cred.SchemeManagerIdentifier()].Valid
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

func (conf *Configuration) pathToDescription(manager *SchemeManager, path string, description interface{}) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}

	relativepath, err := filepath.Rel(conf.Path, path)
	if err != nil {
		return false, err
	}
	bts, found, err := conf.ReadAuthenticatedFile(manager, relativepath)
	if !found {
		if manager.index.Scheme() != manager.Identifier() {
			return false, errors.Errorf("Folder must be called %s, not %s", manager.index.Scheme(), manager.ID)
		}
		return false, errors.Errorf("File %s not present in scheme index", relativepath)
	}
	if err != nil {
		return true, err
	}

	err = xml.Unmarshal(bts, description)
	if err != nil {
		return true, err
	}

	return true, nil
}

// ContainsCredentialType checks if the configuration contains the specified credential type.
func (conf *Configuration) ContainsCredentialType(cred CredentialTypeIdentifier) bool {
	return conf.SchemeManagers[cred.IssuerIdentifier().SchemeManagerIdentifier()] != nil &&
		conf.Issuers[cred.IssuerIdentifier()] != nil &&
		conf.CredentialTypes[cred] != nil
}

func (conf *Configuration) ContainsAttributeType(attr AttributeTypeIdentifier) bool {
	_, contains := conf.AttributeTypes[attr]
	return contains && conf.ContainsCredentialType(attr.CredentialTypeIdentifier())
}

func (conf *Configuration) isUpToDate(scheme SchemeManagerIdentifier) (bool, error) {
	if conf.assets == "" || conf.readOnly {
		return true, nil
	}
	name := scheme.String()
	newTime, exists, err := readTimestamp(filepath.Join(conf.assets, name, "timestamp"))
	if err != nil || !exists {
		return true, errors.WrapPrefix(err, "Could not read asset timestamp of scheme "+name, 0)
	}
	// The storage version of the manager does not need to have a timestamp. If it does not, it is outdated.
	oldTime, exists, err := readTimestamp(filepath.Join(conf.Path, name, "timestamp"))
	if err != nil {
		return true, err
	}
	return exists && !newTime.After(*oldTime), nil
}

func (conf *Configuration) CopyManagerFromAssets(scheme SchemeManagerIdentifier) (bool, error) {
	if conf.assets == "" || conf.readOnly {
		return false, nil
	}
	// Remove old version; we want an exact copy of the assets version
	// not a merge of the assets version and the storage version
	name := scheme.String()
	if err := os.RemoveAll(filepath.Join(conf.Path, name)); err != nil {
		return false, err
	}
	return true, fs.CopyDirectory(
		filepath.Join(conf.assets, name),
		filepath.Join(conf.Path, name),
	)
}

// DownloadSchemeManager downloads and returns a scheme manager description.xml file
// from the specified URL.
func DownloadSchemeManager(url string) (*SchemeManager, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	if strings.HasSuffix(url, "/description.xml") {
		url = url[:len(url)-len("/description.xml")]
	}
	b, err := NewHTTPTransport(url).GetBytes("description.xml")
	if err != nil {
		return nil, err
	}
	manager := NewSchemeManager("")
	if err = xml.Unmarshal(b, manager); err != nil {
		return nil, err
	}

	manager.URL = url // TODO?
	return manager, nil
}

// RemoveSchemeManager removes the specified scheme manager and all associated issuers,
// public keys and credential types from this Configuration.
func (conf *Configuration) RemoveSchemeManager(id SchemeManagerIdentifier, fromStorage bool) error {
	// Remove everything falling under the manager's responsibility
	for credid := range conf.CredentialTypes {
		if credid.IssuerIdentifier().SchemeManagerIdentifier() == id {
			delete(conf.CredentialTypes, credid)
		}
	}
	for issid := range conf.Issuers {
		if issid.SchemeManagerIdentifier() == id {
			delete(conf.Issuers, issid)
		}
	}
	for issid := range conf.publicKeys {
		if issid.SchemeManagerIdentifier() == id {
			delete(conf.publicKeys, issid)
		}
	}
	delete(conf.SchemeManagers, id)

	if fromStorage || !conf.readOnly {
		return os.RemoveAll(fmt.Sprintf("%s/%s", conf.Path, id.String()))
	}
	return nil
}

func (conf *Configuration) ReinstallSchemeManager(manager *SchemeManager) (err error) {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}

	// Check if downloading stuff from the remote works before we uninstall the specified manager:
	// If we can't download anything we should keep the broken version
	manager, err = DownloadSchemeManager(manager.URL)
	if err != nil {
		return
	}
	if err = conf.DeleteSchemeManager(manager.Identifier()); err != nil {
		return
	}
	err = conf.InstallSchemeManager(manager, nil)
	return
}

// InstallSchemeManager downloads and adds the specified scheme manager to this Configuration,
// provided its signature is valid.
func (conf *Configuration) InstallSchemeManager(manager *SchemeManager, publickey []byte) error {
	if conf.readOnly {
		return errors.New("cannot install scheme into a read-only configuration")
	}

	name := manager.ID
	if err := fs.EnsureDirectoryExists(filepath.Join(conf.Path, name)); err != nil {
		return err
	}

	t := NewHTTPTransport(manager.URL)
	path := fmt.Sprintf("%s/%s", conf.Path, name)
	if err := t.GetFile("description.xml", path+"/description.xml"); err != nil {
		return err
	}
	if publickey != nil {
		if err := fs.SaveFile(path+"/pk.pem", publickey); err != nil {
			return err
		}
	} else {
		if err := t.GetFile("pk.pem", path+"/pk.pem"); err != nil {
			return err
		}
	}
	if err := conf.DownloadSchemeManagerSignature(manager); err != nil {
		return err
	}
	conf.SchemeManagers[manager.Identifier()] = manager
	if err := conf.UpdateSchemeManager(manager.Identifier(), nil); err != nil {
		return err
	}

	return conf.ParseSchemeManagerFolder(filepath.Join(conf.Path, name), manager)
}

// DownloadSchemeManagerSignature downloads, stores and verifies the latest version
// of the index file and signature of the specified manager.
func (conf *Configuration) DownloadSchemeManagerSignature(manager *SchemeManager) (err error) {
	if conf.readOnly {
		return errors.New("cannot download into a read-only configuration")
	}

	t := NewHTTPTransport(manager.URL)
	path := fmt.Sprintf("%s/%s", conf.Path, manager.ID)
	index := filepath.Join(path, "index")
	sig := filepath.Join(path, "index.sig")

	if err = t.GetFile("index", index); err != nil {
		return
	}
	if err = t.GetFile("index.sig", sig); err != nil {
		return
	}
	err = conf.VerifySignature(manager.Identifier())
	return
}

func (e *UnknownIdentifierError) Error() string {
	return "Unknown identifiers: " + e.Missing.String()
}

func (e *RequiredAttributeMissingError) Error() string {
	return "Required attributes are missing: " + e.Missing.String()
}

// Download downloads the issuers, credential types and public keys specified in set
// if the current Configuration does not already have them, and checks their authenticity
// using the scheme manager index.
func (conf *Configuration) Download(session SessionRequest) (downloaded *IrmaIdentifierSet, err error) {
	if conf.readOnly {
		return nil, errors.New("Cannot download into a read-only configuration")
	}

	missing, requiredMissing, err := conf.checkIdentifiers(session)
	if err != nil {
		return nil, err
	}
	if len(missing.SchemeManagers) > 0 {
		return nil, &UnknownIdentifierError{ErrorUnknownSchemeManager, missing}
	}

	// Update the scheme found above and parse, if necessary
	downloaded = newIrmaIdentifierSet()

	// Combine to find all identifiers that possibly require updating, i.e.,
	// ones that are not found in the configuration or,
	// ones that were tagged non-optional, but were tagged optional in a more recent configuration
	allMissing := newIrmaIdentifierSet()
	allMissing.join(missing)
	allMissing.join(requiredMissing)

	// Try updating them
	for id := range allMissing.allSchemes() {
		if err = conf.UpdateSchemeManager(id, downloaded); err != nil {
			return
		}
	}
	if !downloaded.Empty() {
		if err = conf.ParseFolder(); err != nil {
			return nil, err
		}
	}

	// Check again if all session identifiers are known now and required attributes are present
	missing, requiredMissing, err = conf.checkIdentifiers(session)
	if err != nil {
		return nil, err
	}

	// Required in the request, but not found in the configuration
	if !missing.Empty() {
		return nil, &UnknownIdentifierError{ErrorUnknownIdentifier, missing}
	}

	// (Still) required in the configuration, but not in the request
	if !requiredMissing.Empty() {
		return nil, &RequiredAttributeMissingError{ErrorRequiredAttributeMissing, requiredMissing}
	}

	return
}

func (conf *Configuration) checkCredentialTypes(session SessionRequest, missing *IrmaIdentifierSet, requiredMissing *IrmaIdentifierSet) {
	var typ *CredentialType
	var contains bool

	switch s := session.(type) {
	case *IssuanceRequest:
		for _, credreq := range s.Credentials {

			// First check if we have this credential type
			typ, contains = conf.CredentialTypes[credreq.CredentialTypeID]
			if !contains {
				missing.CredentialTypes[credreq.CredentialTypeID] = struct{}{}
				continue
			}

			// Check for attributes in the request that are not in the credential configuration
			for reqAttr, _ := range credreq.Attributes {
				attrID := NewAttributeTypeIdentifier(credreq.CredentialTypeID.String() + "." + reqAttr)
				if !typ.ContainsAttribute(attrID) {
					missing.AttributeTypes[attrID] = struct{}{}
				}
			}

			// Check if all attributes from the configuration are present, unless they are marked as optional
			for _, attrtype := range typ.AttributeTypes {
				_, present := credreq.Attributes[attrtype.ID]
				if !present && !attrtype.IsOptional() {
					requiredMissing.AttributeTypes[attrtype.GetAttributeTypeIdentifier()] = struct{}{}
				}
			}
		}
	}

	_ = session.Disclosure().Disclose.Iterate(func(attr *AttributeRequest) error {
		credid := attr.Type.CredentialTypeIdentifier()
		if typ, contains = conf.CredentialTypes[credid]; !contains {
			missing.CredentialTypes[credid] = struct{}{}
			return nil
		}
		if !attr.Type.IsCredential() && !typ.ContainsAttribute(attr.Type) {
			missing.AttributeTypes[attr.Type] = struct{}{}
		}
		return nil
	})

	return
}

func (conf *Configuration) checkIdentifiers(session SessionRequest) (*IrmaIdentifierSet, *IrmaIdentifierSet, error) {
	missing := newIrmaIdentifierSet()
	requiredMissing := newIrmaIdentifierSet()
	conf.checkSchemes(session, missing)
	if err := conf.checkIssuers(session.Identifiers(), missing); err != nil {
		return nil, nil, err
	}
	conf.checkCredentialTypes(session, missing, requiredMissing)
	return missing, requiredMissing, nil
}

// CheckSchemes verifies that all schemes occuring in the specified session request occur in this
// instance.
func (conf *Configuration) checkSchemes(session SessionRequest, missing *IrmaIdentifierSet) {
	for id := range session.Identifiers().SchemeManagers {
		scheme, contains := conf.SchemeManagers[id]
		if !contains || !scheme.Valid {
			missing.SchemeManagers[id] = struct{}{}
		}
	}
}

func (conf *Configuration) checkIssuers(set *IrmaIdentifierSet, missing *IrmaIdentifierSet) error {
	for issid := range set.Issuers {
		if _, contains := conf.Issuers[issid]; !contains {
			missing.Issuers[issid] = struct{}{}
		}
	}
	for issid, keyids := range set.PublicKeys {
		for _, keyid := range keyids {
			pk, err := conf.PublicKey(issid, keyid)
			if err != nil {
				return err
			}
			if pk == nil {
				missing.PublicKeys[issid] = append(missing.PublicKeys[issid], keyid)
			}
		}
	}
	return nil
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

func (i SchemeManagerIndex) Scheme() SchemeManagerIdentifier {
	for p := range i {
		return NewSchemeManagerIdentifier(p[0:strings.Index(p, "/")])
	}
	return NewSchemeManagerIdentifier("")
}

// parseIndex parses the index file of the specified manager.
func (conf *Configuration) parseIndex(name string, manager *SchemeManager) (SchemeManagerIndex, error) {
	path := filepath.Join(conf.Path, name, "index")
	if err := fs.AssertPathExists(path); err != nil {
		return nil, fmt.Errorf("Missing scheme manager index file; tried %s", path)
	}
	indexbts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	index := SchemeManagerIndex(make(map[string]ConfigurationFileHash))
	if err = index.FromString(string(indexbts)); err != nil {
		return nil, err
	}

	return index, conf.checkUnsignedFiles(name, index)
}

func (conf *Configuration) checkUnsignedFiles(name string, index SchemeManagerIndex) error {
	return fs.WalkDir(filepath.Join(conf.Path, name), func(path string, info os.FileInfo) error {
		relpath, err := filepath.Rel(conf.Path, path)
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

func dirInScheme(index SchemeManagerIndex, dir string) bool {
	for indexpath := range index {
		if strings.HasPrefix(indexpath, dir) {
			return true
		}
	}
	return false
}

// These files never occur in a scheme's index
var sigExceptions = []*regexp.Regexp{
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

func (conf *Configuration) VerifySchemeManager(manager *SchemeManager) error {
	err := conf.VerifySignature(manager.Identifier())
	if err != nil {
		return err
	}

	var exists bool
	for file := range manager.index {
		exists, err = fs.PathExists(filepath.Join(conf.Path, file))
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		// Don't care about the actual bytes
		if _, _, err = conf.ReadAuthenticatedFile(manager, file); err != nil {
			return err
		}
	}

	return nil
}

// ReadAuthenticatedFile reads the file at the specified path
// and verifies its authenticity by checking that the file hash
// is present in the (signed) scheme manager index file.
func (conf *Configuration) ReadAuthenticatedFile(manager *SchemeManager, path string) ([]byte, bool, error) {
	signedHash, ok := manager.index[filepath.ToSlash(path)]
	if !ok {
		return nil, false, nil
	}

	bts, err := ioutil.ReadFile(filepath.Join(conf.Path, path))
	if err != nil {
		return nil, true, err
	}
	computedHash := sha256.Sum256(bts)

	if !bytes.Equal(computedHash[:], signedHash) {
		return nil, true, errors.Errorf("Hash of %s does not match scheme manager index", path)
	}
	return bts, true, nil
}

// VerifySignature verifies the signature on the scheme manager index file
// (which contains the SHA256 hashes of all files under this scheme manager,
// which are used for verifying file authenticity).
func (conf *Configuration) VerifySignature(id SchemeManagerIdentifier) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = errors.Errorf("Scheme manager index signature failed to verify: %s", e.Error())
			} else {
				err = errors.New("Scheme manager index signature failed to verify")
			}
		}
	}()

	dir := filepath.Join(conf.Path, id.String())
	if err := fs.AssertPathExists(filepath.Join(dir, "index"), filepath.Join(dir, "index.sig"), filepath.Join(dir, "pk.pem")); err != nil {
		return errors.New("Missing scheme manager index file, signature, or public key")
	}

	// Read and hash index file
	indexbts, err := ioutil.ReadFile(filepath.Join(dir, "index"))
	if err != nil {
		return err
	}

	// Read and parse scheme manager public key
	pkbts, err := ioutil.ReadFile(filepath.Join(dir, "pk.pem"))
	if err != nil {
		return err
	}
	pk, err := signed.UnmarshalPemPublicKey(pkbts)
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

func (hash ConfigurationFileHash) String() string {
	return hex.EncodeToString(hash)
}

func (hash ConfigurationFileHash) Equal(other ConfigurationFileHash) bool {
	return bytes.Equal(hash, other)
}

// UpdateSchemeManager syncs the stored version within the irma_configuration directory
// with the remote version at the scheme manager's URL, downloading and storing
// new and modified files, according to the index files of both versions.
// It stores the identifiers of new or updated credential types or issuers in the second parameter.
// Note: any newly downloaded files are not yet parsed and inserted into conf.
func (conf *Configuration) UpdateSchemeManager(id SchemeManagerIdentifier, downloaded *IrmaIdentifierSet) (err error) {
	if conf.readOnly {
		return errors.New("cannot update a read-only configuration")
	}
	manager, contains := conf.SchemeManagers[id]
	if !contains {
		return errors.Errorf("Cannot update unknown scheme manager %s", id)
	}

	// Check remote timestamp and see if we have to do anything
	transport := NewHTTPTransport(manager.URL + "/")
	timestampBts, err := transport.GetBytes("timestamp")
	if err != nil {
		return err
	}
	timestamp, err := parseTimestamp(timestampBts)
	if err != nil {
		return err
	}
	if !manager.Timestamp.Before(*timestamp) {
		return nil
	}

	// Download the new index and its signature, and check that the new index
	// is validly signed by the new signature
	// By aborting immediately in case of error, and restoring backup versions
	// of the index and signature, we leave our stored copy of the scheme manager
	// intact.
	if err = conf.DownloadSchemeManagerSignature(manager); err != nil {
		return
	}
	newIndex, err := conf.parseIndex(manager.ID, manager)
	if err != nil {
		return
	}

	issPattern := regexp.MustCompile("^([^/]+)/([^/]+)/description\\.xml")
	credPattern := regexp.MustCompile("^([^/]+)/([^/]+)/Issues/([^/]+)/description\\.xml")

	// TODO: how to recover/fix local copy if err != nil below?
	for filename, newHash := range newIndex {
		path := filepath.Join(conf.Path, filename)
		oldHash, known := manager.index[filename]
		var have bool
		have, err = fs.PathExists(path)
		if err != nil {
			return err
		}
		if known && have && oldHash.Equal(newHash) {
			continue // nothing to do, we already have this file
		}
		// Ensure that the folder in which to write the file exists
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		stripped := filename[len(manager.ID)+1:] // Scheme manager URL already ends with its name
		// Download the new file, store it in our own irma_configuration folder
		if err = transport.GetSignedFile(stripped, path, newHash); err != nil {
			return
		}
		// See if the file is a credential type or issuer, and add it to the downloaded set if so
		if downloaded == nil {
			continue
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
	}

	if err := conf.downloadDemoPrivateKeys(manager); err != nil {
		return err
	}

	return
}

func (conf *Configuration) UpdateSchemes() error {
	updated := IrmaIdentifierSet{
		SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
		Issuers:         map[IssuerIdentifier]struct{}{},
		CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
		AttributeTypes:  map[AttributeTypeIdentifier]struct{}{},
	}
	for id := range conf.SchemeManagers {
		Logger.WithField("scheme", id).Info("Auto-updating scheme")
		if err := conf.UpdateSchemeManager(id, &updated); err != nil {
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

// Validation methods containing consistency checks on irma_configuration
func validateDemoPrefix(ts TranslatedString) error {
	prefix := "Demo "
	for _, lang := range validLangs {
		if !strings.HasPrefix(map[string]string(ts)[lang], prefix) {
			return errors.Errorf("value in language %s is not prefixed with '%s'", lang, prefix)
		}
	}
	return nil
}

func (conf *Configuration) validateIssuer(manager *SchemeManager, issuer *Issuer, dir string) error {
	issuerid := issuer.Identifier()
	conf.validateTranslations(fmt.Sprintf("Issuer %s", issuerid.String()), issuer)
	// Check that the issuer has public keys
	pkpath := fmt.Sprintf(pubkeyPattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no public keys", issuerid.String()))
	}

	if filepath.Base(dir) != issuer.ID {
		return errors.Errorf("Issuer %s has wrong directory name %s", issuerid.String(), filepath.Base(dir))
	}
	if manager.ID != issuer.SchemeManagerID {
		return errors.Errorf("Issuer %s has wrong SchemeManager %s", issuerid.String(), issuer.SchemeManagerID)
	}
	if err = validateDemoPrefix(issuer.Name); manager.Demo && err != nil {
		return errors.Errorf("Name of demo issuer %s invalid: %s", issuer.ID, err.Error())
	}
	if err = fs.AssertPathExists(filepath.Join(dir, "logo.png")); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no logo.png", issuerid.String()))
	}
	return nil
}

func (conf *Configuration) validateCredentialType(manager *SchemeManager, issuer *Issuer, cred *CredentialType, dir string) error {
	credid := cred.Identifier()
	conf.validateTranslations(fmt.Sprintf("Credential type %s", credid.String()), cred)
	if cred.XMLVersion < 4 {
		return errors.New("Unsupported credential type description")
	}
	if cred.ID != filepath.Base(dir) {
		return errors.Errorf("Credential type %s has wrong directory name %s", credid.String(), filepath.Base(dir))
	}
	if cred.IssuerID != issuer.ID {
		return errors.Errorf("Credential type %s has wrong IssuerID %s", credid.String(), cred.IssuerID)
	}
	if cred.SchemeManagerID != manager.ID {
		return errors.Errorf("Credential type %s has wrong SchemeManager %s", credid.String(), cred.SchemeManagerID)
	}
	if err := validateDemoPrefix(cred.Name); manager.Demo && err != nil {
		return errors.Errorf("Name of demo credential %s invalid: %s", cred.ID, err.Error())
	}
	if err := fs.AssertPathExists(filepath.Join(dir, "logo.png")); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has no logo.png", credid.String()))
	}
	return conf.validateAttributes(cred)
}

func (conf *Configuration) validateAttributes(cred *CredentialType) error {
	name := cred.Identifier().String()
	indices := make(map[int]struct{})
	count := len(cred.AttributeTypes)
	if count == 0 {
		return errors.Errorf("Credenial type %s has no attributes", name)
	}
	for i, attr := range cred.AttributeTypes {
		conf.validateTranslations(fmt.Sprintf("Attribute %s of credential type %s", attr.ID, cred.Identifier().String()), attr)
		index := i
		if attr.DisplayIndex != nil {
			index = *attr.DisplayIndex
		}
		if index >= count {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute displayIndex at attribute %d", name, i))
		}
		indices[index] = struct{}{}
	}
	if len(indices) != count {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute ordering, check the displayIndex tags", name))
	}
	return nil
}

func (conf *Configuration) validateScheme(scheme *SchemeManager, dir string) error {
	if scheme.XMLVersion < 7 {
		scheme.Status = SchemeManagerStatusParsingError
		return errors.New("Unsupported scheme manager description")
	}
	if filepath.Base(dir) != scheme.ID {
		scheme.Status = SchemeManagerStatusParsingError
		return errors.Errorf("Scheme %s has wrong directory name %s", scheme.ID, filepath.Base(dir))
	}
	if scheme.KeyshareServer != "" {
		if err := fs.AssertPathExists(filepath.Join(dir, "kss-0.pem")); err != nil {
			scheme.Status = SchemeManagerStatusParsingError
			return errors.Errorf("Scheme %s has keyshare URL but no keyshare public key kss-0.pem", scheme.ID)
		}
	}
	conf.validateTranslations(fmt.Sprintf("Scheme %s", scheme.ID), scheme)
	return nil
}

// validateTranslations checks for each member of the interface o that is of type TranslatedString
// that it contains all necessary translations.
func (conf *Configuration) validateTranslations(file string, o interface{}) {
	v := reflect.ValueOf(o)

	// Dereference in case of pointer or interface
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name
		if field.Type() != reflect.TypeOf(TranslatedString{}) || name == "IssueURL" {
			continue
		}
		val := field.Interface().(TranslatedString)
		for _, lang := range validLangs {
			if _, exists := val[lang]; !exists {
				conf.Warnings = append(conf.Warnings, fmt.Sprintf("%s misses %s translation in <%s> tag", file, lang, name))
			}
		}
	}
}

func (conf *Configuration) ValidateKeys() error {
	const expiryBoundary = int64(time.Hour/time.Second) * 24 * 31 // 1 month, TODO make configurable

	for issuerid, issuer := range conf.Issuers {
		if err := conf.parseKeysFolder(issuerid); err != nil {
			return err
		}
		indices, err := conf.PublicKeyIndices(issuerid)
		if err != nil {
			return err
		}
		if len(indices) == 0 {
			continue
		}
		latest, err := conf.PublicKey(issuerid, indices[len(indices)-1])
		if err != nil {
			return err
		}

		// Check expiry date public keys only if issuer is not deprecated
		now := time.Now()
		if issuer.DeprecatedSince.IsZero() || issuer.DeprecatedSince.After(Timestamp(now)) {
			if latest == nil || latest.ExpiryDate < now.Unix() {
				conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no nonexpired public keys", issuerid.String()))
			}
			if latest != nil && latest.ExpiryDate > now.Unix() && latest.ExpiryDate < now.Unix()+expiryBoundary {
				conf.Warnings = append(conf.Warnings, fmt.Sprintf("Latest public key of issuer %s expires soon (at %s)",
					issuerid.String(), time.Unix(latest.ExpiryDate, 0).String()))
			}
		}

		// Check private keys if any
		indices, err = conf.PrivateKeyIndices(issuerid)
		if err != nil {
			return err
		}
		for _, i := range indices {
			sk, err := conf.PrivateKey(issuerid, i)
			if err != nil {
				return err
			}
			if sk.Counter != i {
				return errors.Errorf("Private key %d of issuer %s has wrong <Counter>", i, issuerid.String())
			}
			pk, err := conf.PublicKey(issuerid, i)
			if err != nil {
				return err
			}
			if pk == nil {
				return errors.Errorf("Private key %d of issuer %s has no corresponding public key", i, issuerid.String())
			}
			if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
				return errors.Errorf("Private key %d of issuer %s does not belong to corresponding public key", i, issuerid.String())
			}
			if sk.RevocationSupported() != pk.RevocationSupported() {
				return errors.Errorf("revocation support of private key %d of issuer %s is not consistent with corresponding public key", i, issuerid.String())
			}
		}

		// Check that the current public key supports enough attributes for all credential types
		// issued by this issuer
		for id, typ := range conf.CredentialTypes {
			if id.IssuerIdentifier() != issuerid {
				continue
			}
			if len(typ.AttributeTypes)+2 > len(latest.R) {
				return errors.Errorf("Latest public key of issuer %s does not support the amount of attributes that credential type %s requires (%d, required: %d)", issuerid.String(), id.String(), len(latest.R), len(typ.AttributeTypes)+2)
			}
			pk, err := conf.PublicKeyLatest(typ.IssuerIdentifier())
			if err != nil {
				return err
			}
			if typ.RevocationSupported() && !pk.RevocationSupported() {
				return errors.Errorf("credential type %s supports revocation but latest private key of issuer %s does not", typ.Identifier(), issuerid)
			}
		}
	}

	return nil
}

// DefaultDataPath returns the default storage path for IRMA, using XDG Base Directory Specification
// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html:
//  - %LOCALAPPDATA% (i.e. C:\Users\$user\AppData\Local) if on Windows,
//  - $XDG_DATA_HOME if set, otherwise $HOME/.local/share
//  - $XDG_DATA_DIRS if set, otherwise /usr/local/share/ and /usr/share/
//  - then the OSes temp dir (os.TempDir()),
// returning the first of these that exists or can be created.
func DefaultDataPath() string {
	candidates := make([]string, 0, 8)
	home := os.Getenv("HOME")
	xdgDataHome := os.Getenv("XDG_DATA_HOME")
	xdgDataDirs := os.Getenv("XDG_DATA_DIRS")

	if runtime.GOOS == "windows" {
		appdata := os.Getenv("LOCALAPPDATA") // C:\Users\$user\AppData\Local
		if appdata != "" {
			candidates = append(candidates, appdata)
		}
	}

	if xdgDataHome != "" {
		candidates = append(candidates, xdgDataHome)
	}
	if xdgDataHome == "" && home != "" {
		candidates = append(candidates, filepath.Join(home, ".local", "share"))
	}
	if xdgDataDirs != "" {
		candidates = append(candidates, strings.Split(xdgDataDirs, ":")...)
	} else {
		candidates = append(candidates, "/usr/local/share", "/usr/share")
	}
	candidates = append(candidates, filepath.Join(os.TempDir()))

	for i := range candidates {
		candidates[i] = filepath.Join(candidates[i], "irma")
	}

	return firstExistingPath(candidates)
}

// DefaultSchemesPath returns the default storage path for irma_configuration,
// namely DefaultDataPath + "/irma_configuration"
func DefaultSchemesPath() string {
	p := DefaultDataPath()
	if p == "" {
		return p
	}
	p = filepath.Join(p, "irma_configuration")
	if err := fs.EnsureDirectoryExists(p); err != nil {
		return ""
	}
	return p
}

func firstExistingPath(paths []string) string {
	for _, path := range paths {
		if err := fs.EnsureDirectoryExists(path); err == nil {
			return path
		}
	}
	return ""
}
