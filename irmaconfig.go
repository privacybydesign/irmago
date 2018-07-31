package irma

import (
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"crypto/sha256"

	"fmt"

	"strings"

	"sort"

	"bytes"

	"encoding/hex"

	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago/internal/fs"
)

// Configuration keeps track of scheme managers, issuers, credential types and public keys,
// dezerializing them from an irma_configuration folder, and downloads and saves new ones on demand.
type Configuration struct {
	SchemeManagers  map[SchemeManagerIdentifier]*SchemeManager
	Issuers         map[IssuerIdentifier]*Issuer
	CredentialTypes map[CredentialTypeIdentifier]*CredentialType

	// Path to the irma_configuration folder that this instance represents
	Path string

	// DisabledSchemeManagers keeps track of scheme managers that did not parse  succesfully
	// (i.e., invalid signature, parsing error), and the problem that occurred when parsing them
	DisabledSchemeManagers map[SchemeManagerIdentifier]*SchemeManagerError

	Warnings []string

	publicKeys    map[IssuerIdentifier]map[int]*gabi.PublicKey
	reverseHashes map[string]CredentialTypeIdentifier
	initialized   bool
	assets        string
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

func (sme SchemeManagerError) Error() string {
	return fmt.Sprintf("Error parsing scheme manager %s: %s", sme.Manager.Name(), sme.Err.Error())
}

// NewConfiguration returns a new configuration. After this
// ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string, assets string) (conf *Configuration, err error) {
	conf = &Configuration{
		Path:   path,
		assets: assets,
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
	conf.DisabledSchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManagerError)
	conf.publicKeys = make(map[IssuerIdentifier]map[int]*gabi.PublicKey)
	conf.reverseHashes = make(map[string]CredentialTypeIdentifier)
}

// ParseFolder populates the current Configuration by parsing the storage path,
// listing the containing scheme managers, issuers and credential types.
func (conf *Configuration) ParseFolder() (err error) {
	// Init all maps
	conf.clear()

	// Copy any new or updated scheme managers out of the assets into storage
	if conf.assets != "" {
		err = iterateSubfolders(conf.assets, func(dir string) error {
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
	err = iterateSubfolders(conf.Path, func(dir string) error {
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
	if !exists {
		manager.Status = SchemeManagerStatusParsingError
		return errors.New("Scheme manager description not found")
	}
	if err != nil {
		manager.Status = SchemeManagerStatusParsingError
		return
	}
	if err = conf.checkScheme(manager, dir); err != nil {
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

func relativePath(absolute string, relative string) string {
	return relative[len(absolute)+1:]
}

// PublicKey returns the specified public key, or nil if not present in the Configuration.
func (conf *Configuration) PublicKey(id IssuerIdentifier, counter int) (*gabi.PublicKey, error) {
	if _, contains := conf.publicKeys[id]; !contains {
		if err := conf.parseKeysFolder(conf.SchemeManagers[id.SchemeManagerIdentifier()], id); err != nil {
			return nil, err
		}
	}
	return conf.publicKeys[id][counter], nil
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
	return iterateSubfolders(path, func(dir string) error {
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

		if err = conf.checkIssuer(manager, issuer, dir); err != nil {
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
	return os.RemoveAll(filepath.Join(conf.Path, id.Name()))
}

// parse $schememanager/$issuer/PublicKeys/$i.xml for $i = 1, ...
func (conf *Configuration) parseKeysFolder(manager *SchemeManager, issuerid IssuerIdentifier) error {
	conf.publicKeys[issuerid] = map[int]*gabi.PublicKey{}
	path := fmt.Sprintf(pubkeyPattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(path)
	if err != nil {
		return err
	}

	for _, file := range files {
		filename := filepath.Base(file)
		count := filename[:len(filename)-4]
		i, err := strconv.Atoi(count)
		if err != nil {
			return err
		}
		bts, found, err := conf.ReadAuthenticatedFile(manager, relativePath(conf.Path, file))
		if err != nil || !found {
			return err
		}
		pk, err := gabi.NewPublicKeyFromBytes(bts)
		if err != nil {
			return err
		}
		if int(pk.Counter) != i {
			return errors.Errorf("Public key %s of issuer %s has wrong <Counter>", file, issuerid.String())
		}
		pk.Issuer = issuerid.String()
		conf.publicKeys[issuerid][i] = pk
	}

	return nil
}

func (conf *Configuration) PublicKeyIndices(issuerid IssuerIdentifier) (i []int, err error) {
	return conf.matchKeyPattern(issuerid, pubkeyPattern)
}

func (conf *Configuration) matchKeyPattern(issuerid IssuerIdentifier, pattern string) (i []int, err error) {
	pkpath := fmt.Sprintf(pattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return
	}
	for _, file := range files {
		var count int
		base := filepath.Base(file)
		if count, err = strconv.Atoi(base[:len(base)-4]); err != nil {
			return
		}
		i = append(i, count)
	}
	sort.Ints(i)
	return
}

// parse $schememanager/$issuer/Issues/*/description.xml
func (conf *Configuration) parseCredentialsFolder(manager *SchemeManager, issuer *Issuer, path string) error {
	var foundcred bool
	err := iterateSubfolders(path, func(dir string) error {
		cred := &CredentialType{}
		exists, err := conf.pathToDescription(manager, dir+"/description.xml", cred)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err = conf.checkCredentialType(manager, issuer, cred, dir); err != nil {
			return err
		}
		foundcred = true
		cred.Valid = conf.SchemeManagers[cred.SchemeManagerIdentifier()].Valid
		credid := cred.Identifier()
		conf.CredentialTypes[credid] = cred
		conf.addReverseHash(credid)
		return nil
	})
	if !foundcred {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no credential types", issuer.Identifier().String()))
	}
	return err
}

// iterateSubfolders iterates over the subfolders of the specified path,
// calling the specified handler each time. If anything goes wrong, or
// if the caller returns a non-nil error, an error is immediately returned.
func iterateSubfolders(path string, handler func(string) error) error {
	dirs, err := filepath.Glob(path + "/*")
	if err != nil {
		return err
	}

	for _, dir := range dirs {
		stat, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !stat.IsDir() {
			continue
		}
		if strings.HasSuffix(dir, "/.git") {
			continue
		}
		err = handler(dir)
		if err != nil {
			return err
		}
	}

	return nil
}

func (conf *Configuration) pathToDescription(manager *SchemeManager, path string, description interface{}) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}

	bts, found, err := conf.ReadAuthenticatedFile(manager, relativePath(conf.Path, path))
	if !found {
		return false, nil
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

// Contains checks if the configuration contains the specified credential type.
func (conf *Configuration) Contains(cred CredentialTypeIdentifier) bool {
	return conf.SchemeManagers[cred.IssuerIdentifier().SchemeManagerIdentifier()] != nil &&
		conf.Issuers[cred.IssuerIdentifier()] != nil &&
		conf.CredentialTypes[cred] != nil
}

func (conf *Configuration) isUpToDate(scheme SchemeManagerIdentifier) (bool, error) {
	if conf.assets == "" {
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
	if conf.assets == "" {
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

	if fromStorage {
		return os.RemoveAll(fmt.Sprintf("%s/%s", conf.Path, id.String()))
	}
	return nil
}

func (conf *Configuration) ReinstallSchemeManager(manager *SchemeManager) (err error) {
	// Check if downloading stuff from the remote works before we uninstall the specified manager:
	// If we can't download anything we should keep the broken version
	manager, err = DownloadSchemeManager(manager.URL)
	if err != nil {
		return
	}
	if err = conf.DeleteSchemeManager(manager.Identifier()); err != nil {
		return
	}
	err = conf.InstallSchemeManager(manager)
	return
}

// InstallSchemeManager downloads and adds the specified scheme manager to this Configuration,
// provided its signature is valid.
func (conf *Configuration) InstallSchemeManager(manager *SchemeManager) error {
	name := manager.ID
	if err := fs.EnsureDirectoryExists(filepath.Join(conf.Path, name)); err != nil {
		return err
	}

	t := NewHTTPTransport(manager.URL)
	path := fmt.Sprintf("%s/%s", conf.Path, name)
	if err := t.GetFile("description.xml", path+"/description.xml"); err != nil {
		return err
	}
	if err := t.GetFile("pk.pem", path+"/pk.pem"); err != nil {
		return err
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

// Download downloads the issuers, credential types and public keys specified in set
// if the current Configuration does not already have them,  and checks their authenticity
// using the scheme manager index.
func (conf *Configuration) Download(session IrmaSession) (downloaded *IrmaIdentifierSet, err error) {
	managers := make(map[string]struct{}) // Managers that we must update
	downloaded = &IrmaIdentifierSet{
		SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
		Issuers:         map[IssuerIdentifier]struct{}{},
		CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
	}

	// Calculate which scheme managers must be updated
	if err = conf.checkIssuers(session.Identifiers(), managers); err != nil {
		return
	}
	if err = conf.checkCredentialTypes(session, managers); err != nil {
		return
	}

	// Update the scheme managers found above and parse them, if necessary
	for id := range managers {
		if err = conf.UpdateSchemeManager(NewSchemeManagerIdentifier(id), downloaded); err != nil {
			return
		}
	}
	if !downloaded.Empty() {
		return downloaded, conf.ParseFolder()
	}
	return
}

func (conf *Configuration) checkCredentialTypes(session IrmaSession, managers map[string]struct{}) error {
	var disjunctions AttributeDisjunctionList
	var typ *CredentialType
	var contains bool

	switch s := session.(type) {
	case *IssuanceRequest:
		for _, credreq := range s.Credentials {
			// First check if we have this credential type
			typ, contains = conf.CredentialTypes[*credreq.CredentialTypeID]
			if !contains {
				managers[credreq.CredentialTypeID.Root()] = struct{}{}
				continue
			}
			newAttrs := make(map[string]string)
			for k, v := range credreq.Attributes {
				newAttrs[k] = v
			}
			// For each of the attributes in the credentialtype, see if it is present; if so remove it from newAttrs
			// If not, check that it is optional; if not the credentialtype must be updated
			for _, attrtyp := range typ.Attributes {
				_, contains = newAttrs[attrtyp.ID]
				if !contains && !attrtyp.IsOptional() {
					managers[credreq.CredentialTypeID.Root()] = struct{}{}
					break
				}
				delete(newAttrs, attrtyp.ID)
			}
			// If there is anything left in newAttrs, then these are attributes that are not in the credentialtype
			if len(newAttrs) > 0 {
				managers[credreq.CredentialTypeID.Root()] = struct{}{}
			}
		}
		disjunctions = s.Disclose
	case *DisclosureRequest:
		disjunctions = s.Content
	case *SignatureRequest:
		disjunctions = s.Content
	}

	for _, disjunction := range disjunctions {
		for _, attrid := range disjunction.Attributes {
			credid := attrid.CredentialTypeIdentifier()
			if typ, contains = conf.CredentialTypes[credid]; !contains {
				managers[credid.Root()] = struct{}{}
			}
			if !typ.ContainsAttribute(attrid) {
				managers[credid.Root()] = struct{}{}
			}
		}
	}

	return nil
}

func (conf *Configuration) checkIssuers(set *IrmaIdentifierSet, managers map[string]struct{}) error {
	for issid := range set.Issuers {
		if _, contains := conf.Issuers[issid]; !contains {
			managers[issid.Root()] = struct{}{}
		}
	}
	for issid, keyids := range set.PublicKeys {
		for _, keyid := range keyids {
			pk, err := conf.PublicKey(issid, keyid)
			if err != nil {
				return err
			}
			if pk == nil {
				managers[issid.Root()] = struct{}{}
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
	return index, index.FromString(string(indexbts))
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
	if err := fs.AssertPathExists(dir+"/index", dir+"/index.sig", dir+"/pk.pem"); err != nil {
		return errors.New("Missing scheme manager index file, signature, or public key")
	}

	// Read and hash index file
	indexbts, err := ioutil.ReadFile(dir + "/index")
	if err != nil {
		return err
	}
	indexhash := sha256.Sum256(indexbts)

	// Read and parse scheme manager public key
	pkbts, err := ioutil.ReadFile(dir + "/pk.pem")
	if err != nil {
		return err
	}
	pkblk, _ := pem.Decode(pkbts)
	genericPk, err := x509.ParsePKIXPublicKey(pkblk.Bytes)
	if err != nil {
		return err
	}
	pk, ok := genericPk.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("Invalid scheme manager public key")
	}

	// Read and parse signature
	sig, err := ioutil.ReadFile(dir + "/index.sig")
	if err != nil {
		return err
	}
	ints := make([]*big.Int, 0, 2)
	_, err = asn1.Unmarshal(sig, &ints)

	// Verify signature
	if !ecdsa.Verify(pk, indexhash[:], ints[0], ints[1]) {
		return errors.New("Scheme manager signature was invalid")
	}
	return nil
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

	issPattern := regexp.MustCompile("(.+)/(.+)/description\\.xml")
	credPattern := regexp.MustCompile("(.+)/(.+)/Issues/(.+)/description\\.xml")

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
		matches = issPattern.FindStringSubmatch(filename)
		if len(matches) == 3 {
			issid := NewIssuerIdentifier(fmt.Sprintf("%s.%s", matches[1], matches[2]))
			downloaded.Issuers[issid] = struct{}{}
		}
		matches = credPattern.FindStringSubmatch(filename)
		if len(matches) == 4 {
			credid := NewCredentialTypeIdentifier(fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3]))
			downloaded.CredentialTypes[credid] = struct{}{}
		}
	}

	manager.index = newIndex
	return
}

// Methods containing consistency checks on irma_configuration

func (conf *Configuration) checkIssuer(manager *SchemeManager, issuer *Issuer, dir string) error {
	issuerid := issuer.Identifier()
	conf.checkTranslations(fmt.Sprintf("Issuer %s", issuerid.String()), issuer)
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
	if err = fs.AssertPathExists(dir + "/logo.png"); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no logo.png", issuerid.String()))
	}
	return nil
}

func (conf *Configuration) checkCredentialType(manager *SchemeManager, issuer *Issuer, cred *CredentialType, dir string) error {
	credid := cred.Identifier()
	conf.checkTranslations(fmt.Sprintf("Credential type %s", credid.String()), cred)
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
	if err := fs.AssertPathExists(dir + "/logo.png"); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has no logo.png", credid.String()))
	}
	return conf.checkAttributes(cred)
}

func (conf *Configuration) checkAttributes(cred *CredentialType) error {
	name := cred.Identifier().String()
	indices := make(map[int]struct{})
	count := len(cred.Attributes)
	if count == 0 {
		return errors.Errorf("Credenial type %s has no attributes", name)
	}
	for i, attr := range cred.Attributes {
		conf.checkTranslations(fmt.Sprintf("Attribute %s of credential type %s", attr.ID, cred.Identifier().String()), attr)
		index := i
		if attr.Index != nil {
			index = *attr.Index
		}
		if index >= count {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute index at attribute %d", name, i))
		}
		indices[index] = struct{}{}
	}
	if len(indices) != count {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute ordering, check the index-tags", name))
	}
	return nil
}

func (conf *Configuration) checkScheme(scheme *SchemeManager, dir string) error {
	if scheme.XMLVersion < 7 {
		scheme.Status = SchemeManagerStatusParsingError
		return errors.New("Unsupported scheme manager description")
	}
	if filepath.Base(dir) != scheme.ID {
		scheme.Status = SchemeManagerStatusParsingError
		return errors.Errorf("Scheme %s has wrong directory name %s", scheme.ID, filepath.Base(dir))
	}
	conf.checkTranslations(fmt.Sprintf("Scheme %s", scheme.ID), scheme)
	return nil
}

// checkTranslations checks for each member of the interface o that is of type TranslatedString
// that it contains all necessary translations.
func (conf *Configuration) checkTranslations(file string, o interface{}) {
	langs := []string{"en", "nl"} // Hardcode these for now, TODO make configurable
	v := reflect.ValueOf(o)

	// Dereference in case of pointer or interface
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}

	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Type() == reflect.TypeOf(TranslatedString{}) {
			val := v.Field(i).Interface().(TranslatedString)
			for _, lang := range langs {
				if _, exists := val[lang]; !exists {
					conf.Warnings = append(conf.Warnings, fmt.Sprintf("%s misses %s translation in <%s> tag", file, lang, v.Type().Field(i).Name))
				}
			}
		}
	}
}

func (conf *Configuration) CheckKeys() error {
	const expiryBoundary = int64(time.Hour/time.Second) * 24 * 31 // 1 month, TODO make configurable

	for issuerid := range conf.Issuers {
		if err := conf.parseKeysFolder(conf.SchemeManagers[issuerid.SchemeManagerIdentifier()], issuerid); err != nil {
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
		now := time.Now().Unix()
		if latest == nil || latest.ExpiryDate < now {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no nonexpired public keys", issuerid.String()))
		}
		if latest != nil && latest.ExpiryDate > now && latest.ExpiryDate < now+expiryBoundary {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("Latest public key of issuer %s expires soon (at %s)",
				issuerid.String(), time.Unix(latest.ExpiryDate, 0).String()))
		}

		// Check private keys if any
		privkeypath := fmt.Sprintf(privkeyPattern, conf.Path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
		privkeys, err := filepath.Glob(privkeypath)
		if err != nil {
			return err
		}
		for _, privkey := range privkeys {
			filename := filepath.Base(privkey)
			count, err := strconv.Atoi(filename[:len(filename)-4])
			if err != nil {
				return err
			}
			sk, err := gabi.NewPrivateKeyFromFile(privkey)
			if err != nil {
				return err
			}
			if int(sk.Counter) != count {
				return errors.Errorf("Private key %s of issuer %s has wrong <Counter>", filename, issuerid.String())
			}
			pk, err := conf.PublicKey(issuerid, count)
			if err != nil {
				return err
			}
			if pk == nil {
				return errors.Errorf("Private key %s of issuer %s has no corresponding public key", filename, issuerid.String())
			}
			if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
				return errors.Errorf("Private key %s of issuer %s does not belong to public key %s", filename, issuerid.String(), filename)
			}
		}
	}

	return nil
}
