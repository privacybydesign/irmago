package irma

import (
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"crypto/sha256"

	"fmt"

	"strings"

	"github.com/credentials/irmago/internal/fs"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// Configuration keeps track of scheme managers, issuers, credential types and public keys,
// dezerializing them from an irma_configuration folder, and downloads and saves new ones on demand.
type Configuration struct {
	SchemeManagers  map[SchemeManagerIdentifier]*SchemeManager
	Issuers         map[IssuerIdentifier]*Issuer
	CredentialTypes map[CredentialTypeIdentifier]*CredentialType

	publicKeys    map[IssuerIdentifier]map[int]*gabi.PublicKey
	reverseHashes map[string]CredentialTypeIdentifier
	path          string
	initialized   bool
}

// NewConfiguration returns a new configuration. After this
// ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string, assets string) (conf *Configuration, err error) {
	conf = &Configuration{
		path: path,
	}

	if err = fs.EnsureDirectoryExists(conf.path); err != nil {
		return nil, err
	}
	if assets != "" {
		if err = conf.Copy(assets, false); err != nil {
			return nil, err
		}
	}

	return
}

// ParseFolder populates the current Configuration by parsing the storage path,
// listing the containing scheme managers, issuers and credential types.
func (conf *Configuration) ParseFolder() error {
	// Init all maps
	conf.SchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManager)
	conf.Issuers = make(map[IssuerIdentifier]*Issuer)
	conf.CredentialTypes = make(map[CredentialTypeIdentifier]*CredentialType)
	conf.publicKeys = make(map[IssuerIdentifier]map[int]*gabi.PublicKey)

	conf.reverseHashes = make(map[string]CredentialTypeIdentifier)

	err := iterateSubfolders(conf.path, func(dir string) error {
		manager := &SchemeManager{}
		exists, err := pathToDescription(dir+"/description.xml", manager)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if manager.XMLVersion < 7 {
			return errors.New("Unsupported scheme manager description")
		}
		conf.SchemeManagers[manager.Identifier()] = manager
		return conf.parseIssuerFolders(dir)
	})
	if err != nil {
		return err
	}
	conf.initialized = true
	return nil
}

// PublicKey returns the specified public key, or nil if not present in the Configuration.
func (conf *Configuration) PublicKey(id IssuerIdentifier, counter int) (*gabi.PublicKey, error) {
	if _, contains := conf.publicKeys[id]; !contains {
		conf.publicKeys[id] = map[int]*gabi.PublicKey{}
		if err := conf.parseKeysFolder(id); err != nil {
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

func (conf *Configuration) parseIssuerFolders(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		issuer := &Issuer{}
		exists, err := pathToDescription(dir+"/description.xml", issuer)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if issuer.XMLVersion < 4 {
			return errors.New("Unsupported issuer description")
		}
		conf.Issuers[issuer.Identifier()] = issuer
		return conf.parseCredentialsFolder(dir + "/Issues/")
	})
}

// parse $schememanager/$issuer/PublicKeys/$i.xml for $i = 1, ...
func (conf *Configuration) parseKeysFolder(issuerid IssuerIdentifier) error {
	path := fmt.Sprintf("%s/%s/%s/PublicKeys/*.xml", conf.path, issuerid.SchemeManagerIdentifier().Name(), issuerid.Name())
	files, err := filepath.Glob(path)
	if err != nil {
		return err
	}

	for _, file := range files {
		filename := filepath.Base(file)
		count := filename[:len(filename)-4]
		i, err := strconv.Atoi(count)
		if err != nil {
			continue
		}
		pk, err := gabi.NewPublicKeyFromFile(file)
		if err != nil {
			return err
		}
		pk.Issuer = issuerid.String()
		conf.publicKeys[issuerid][i] = pk
	}

	return nil
}

// parse $schememanager/$issuer/Issues/*/description.xml
func (conf *Configuration) parseCredentialsFolder(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		cred := &CredentialType{}
		exists, err := pathToDescription(dir+"/description.xml", cred)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if cred.XMLVersion < 4 {
			return errors.New("Unsupported credential type description")
		}
		credid := cred.Identifier()
		conf.CredentialTypes[credid] = cred
		conf.addReverseHash(credid)
		return nil
	})
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
		err = handler(dir)
		if err != nil {
			return err
		}
	}

	return nil
}

func pathToDescription(path string, description interface{}) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return true, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return true, err
	}

	err = xml.Unmarshal(bytes, description)
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

func (conf *Configuration) Copy(source string, parse bool) error {
	if err := fs.EnsureDirectoryExists(conf.path); err != nil {
		return err
	}

	err := filepath.Walk(source, filepath.WalkFunc(
		func(path string, info os.FileInfo, err error) error {
			if path == source {
				return nil
			}
			subpath := path[len(source):]
			if info.IsDir() {
				if err := fs.EnsureDirectoryExists(conf.path + subpath); err != nil {
					return err
				}
			} else {
				srcfile, err := os.Open(path)
				if err != nil {
					return err
				}
				defer srcfile.Close()
				bytes, err := ioutil.ReadAll(srcfile)
				if err != nil {
					return err
				}
				if err := fs.SaveFile(conf.path+subpath, bytes); err != nil {
					return err
				}
			}
			return nil
		}),
	)

	if err != nil {
		return err
	}
	if parse {
		return conf.ParseFolder()
	}
	return nil
}

func (conf *Configuration) DownloadSchemeManager(url string) (*SchemeManager, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	if strings.HasSuffix(url, "/description.xml") {
		url = url[:len(url)-len("/description.xml")]
	}
	b, err := NewHTTPTransport(url).GetBytes("/description.xml")
	if err != nil {
		return nil, err
	}
	manager := &SchemeManager{}
	if err = xml.Unmarshal(b, manager); err != nil {
		return nil, err
	}

	manager.URL = url // TODO?
	return manager, nil
}

func (conf *Configuration) RemoveSchemeManager(id SchemeManagerIdentifier) error {
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
	// Remove from storage
	return os.RemoveAll(fmt.Sprintf("%s/%s", conf.path, id.String()))
	// or, remove above iterations and call .ParseFolder()?
}

func (conf *Configuration) AddSchemeManager(manager *SchemeManager) error {
	name := manager.ID
	if err := fs.EnsureDirectoryExists(fmt.Sprintf("%s/%s", conf.path, name)); err != nil {
		return err
	}
	b, err := xml.Marshal(manager)
	if err != nil {
		return err
	}
	if err := fs.SaveFile(fmt.Sprintf("%s/%s/description.xml", conf.path, name), b); err != nil {
		return err
	}
	conf.SchemeManagers[NewSchemeManagerIdentifier(name)] = manager
	return nil
}

func (conf *Configuration) Download(set *IrmaIdentifierSet) (*IrmaIdentifierSet, error) {
	var contains bool
	var err error
	downloaded := &IrmaIdentifierSet{
		SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
		Issuers:         map[IssuerIdentifier]struct{}{},
		CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
	}

	for manid := range set.SchemeManagers {
		if _, contains = conf.SchemeManagers[manid]; !contains {
			return nil, errors.Errorf("Unknown scheme manager: %s", manid)
		}
	}

	transport := NewHTTPTransport("")
	for issid := range set.Issuers {
		if _, contains = conf.Issuers[issid]; !contains {
			url := conf.SchemeManagers[issid.SchemeManagerIdentifier()].URL + "/" + issid.Name()
			path := fmt.Sprintf("%s/%s/%s", conf.path, issid.SchemeManagerIdentifier().String(), issid.Name())
			if err = transport.GetFile(url+"/description.xml", path+"/description.xml"); err != nil {
				return nil, err
			}
			if transport.GetFile(url+"/logo.png", path+"/logo.png"); err != nil {
				return nil, err
			}
			downloaded.Issuers[issid] = struct{}{}
		}
	}
	for issid, list := range set.PublicKeys {
		for _, count := range list {
			pk, err := conf.PublicKey(issid, count)
			if err != nil {
				return nil, err
			}
			if pk == nil {
				manager := issid.SchemeManagerIdentifier()
				suffix := fmt.Sprintf("/%s/PublicKeys/%d.xml", issid.Name(), count)
				path := fmt.Sprintf("%s/%s/%s", conf.path, manager.String(), suffix)
				if transport.GetFile(conf.SchemeManagers[manager].URL+suffix, path); err != nil {
					return nil, err
				}
			}
		}
	}
	for credid := range set.CredentialTypes {
		if _, contains := conf.CredentialTypes[credid]; !contains {
			issuer := credid.IssuerIdentifier()
			manager := issuer.SchemeManagerIdentifier()
			local := fmt.Sprintf("%s/%s/%s/Issues", conf.path, manager.Name(), issuer.Name())
			if err := fs.EnsureDirectoryExists(local); err != nil {
				return nil, err
			}
			if transport.GetFile(
				fmt.Sprintf("%s/%s/Issues/%s/description.xml",
					conf.SchemeManagers[manager].URL, issuer.Name(), credid.Name()),
				fmt.Sprintf("%s/%s/description.xml", local, credid.Name()),
			); err != nil {
				return nil, err
			}
			downloaded.CredentialTypes[credid] = struct{}{}
		}
	}

	return downloaded, conf.ParseFolder()
}
