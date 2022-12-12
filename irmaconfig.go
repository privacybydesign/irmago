package irma

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/privacybydesign/irmago/internal/concmap"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/irmago/internal/common"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Configuration keeps track of schemes, issuers, credential types and public keys,
// dezerializing them from an irma_configuration folder, and downloads and saves new ones on demand.
type Configuration struct {
	SchemeManagers  map[SchemeManagerIdentifier]*SchemeManager
	Issuers         map[IssuerIdentifier]*Issuer
	CredentialTypes map[CredentialTypeIdentifier]*CredentialType
	AttributeTypes  map[AttributeTypeIdentifier]*AttributeType
	kssPublicKeys   map[SchemeManagerIdentifier]map[int]*rsa.PublicKey
	publicKeys      concmap.ConcMap[PublicKeyIdentifier, *gabikeys.PublicKey]
	reverseHashes   map[string]CredentialTypeIdentifier

	// RequestorScheme data of the currently loaded requestorscheme
	RequestorSchemes map[RequestorSchemeIdentifier]*RequestorScheme
	Requestors       map[string]*RequestorInfo

	IssueWizards map[IssueWizardIdentifier]*IssueWizard

	// DisabledRequestorSchemes keeps track of any error of the requestorscheme if it
	// did not parse successfully
	DisabledRequestorSchemes map[RequestorSchemeIdentifier]*SchemeManagerError
	// DisabledSchemeManagers keeps track of schemes that did not parse successfully
	// (i.e., invalid signature, parsing error), and the problem that occurred when parsing them
	DisabledSchemeManagers map[SchemeManagerIdentifier]*SchemeManagerError

	// Listeners for configuration changes from initialization and updating of the schemes
	UpdateListeners []ConfigurationListener

	// Path to the irma_configuration folder that this instance represents
	Path        string
	PrivateKeys PrivateKeyRing
	Revocation  *RevocationStorage `json:"-"`
	Scheduler   *gocron.Scheduler
	Warnings    []string `json:"-"`

	options     ConfigurationOptions
	initialized bool
	assets      string
	readOnly    bool
}

// ConfigurationListeners are the interface provided to react to changes in schemes.
type ConfigurationListener func(conf *Configuration)

type UnknownIdentifierError struct {
	ErrorType
	Missing *IrmaIdentifierSet
}

type RequiredAttributeMissingError struct {
	ErrorType
	Missing *IrmaIdentifierSet
}

type ConfigurationOptions struct {
	Assets              string
	ReadOnly            bool
	IgnorePrivateKeys   bool
	RevocationDBConnStr string
	RevocationDBType    string
	RevocationSettings  RevocationSettings
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
		if err = common.AssertPathExists(conf.assets); err != nil {
			return nil, errors.WrapPrefix(err, "Nonexistent assets folder specified", 0)
		}
	}
	if err = common.EnsureDirectoryExists(conf.Path); err != nil {
		return nil, err
	}

	// Init all maps
	conf.clear()

	return
}

// ParseFolder populates the current Configuration by parsing the storage path,
// listing the containing schemes, issuers and credential types.
func (conf *Configuration) ParseFolder() (err error) {
	// Init all maps
	conf.clear()

	// Copy any new or updated schemes out of the assets into storage
	if conf.assets != "" {
		err = common.IterateSubfolders(conf.assets, func(dir string, _ os.FileInfo) error {
			uptodate, err := conf.isUpToDate(filepath.Base(dir))
			if err != nil {
				return err
			}
			if !uptodate {
				_, err = conf.copyFromAssets(filepath.Base(dir))
			}
			return err
		})
		if err != nil {
			return err
		}
	}

	// Since requestor schemes may contain information defined in issuer schemes, first check
	// what schemes exist so we can parse issuer schemes first.
	var mgrerr *SchemeManagerError
	var issuerschemes, requestorschemes []Scheme
	err = common.IterateSubfolders(conf.Path, func(dir string, _ os.FileInfo) error {
		scheme, _, err := conf.parseSchemeDescription(dir)
		if err != nil {
			return err
		}
		switch scheme.typ() {
		case SchemeTypeIssuer:
			issuerschemes = append(issuerschemes, scheme)
		case SchemeTypeRequestor:
			requestorschemes = append(requestorschemes, scheme)
		default:
			return errors.New("unsupported scheme type")
		}
		return nil
	})
	if err != nil {
		return
	}

	// Parse the schemes we found, issuer schemes first
	for _, scheme := range append(issuerschemes, requestorschemes...) {
		_, err := conf.ParseSchemeFolder(scheme.path())
		if err == nil {
			continue // OK, do next scheme folder
		}
		// If there is an error, and it is of type SchemeManagerError, return nil
		// so as to continue parsing other schemes.
		if e, ok := err.(*SchemeManagerError); ok {
			mgrerr = e
			continue
		}
		return err // Not a SchemeManagerError? return it & halt parsing now
	}

	if !conf.options.IgnorePrivateKeys && len(conf.PrivateKeys.(*privateKeyRingMerge).rings) == 0 {
		ring, err := newPrivateKeyRingScheme(conf)
		if err != nil {
			return err
		}
		conf.PrivateKeys.(*privateKeyRingMerge).Add(ring)
	}

	if conf.Revocation == nil {
		conf.Scheduler = gocron.NewScheduler(time.UTC)
		conf.Scheduler.StartAsync()
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
	conf.CallListeners()
	if mgrerr != nil {
		return mgrerr
	}
	return
}

// ParseOrRestoreFolder parses the irma_configuration folder, and when possible attempts to restore
// any broken schemes from their remote.
// Any error encountered during parsing is considered recoverable only if it is of type *SchemeManagerError;
// In this case the scheme in which it occurred is downloaded from its remote and re-parsed.
// If any other error is encountered at any time, it is returned immediately.
// If no error is returned, parsing and possibly restoring has been successful, and there should be no
// disabled schemes.
func (conf *Configuration) ParseOrRestoreFolder() (rerr error) {
	err := conf.ParseFolder()
	// Only in case of a *SchemeManagerError might we be able to recover
	if _, isSchemeMgrErr := err.(*SchemeManagerError); !isSchemeMgrErr {
		return err
	}
	if err != nil && (conf.assets == "" || conf.readOnly) {
		return err
	}

	for id := range conf.DisabledSchemeManagers {
		if err = conf.reinstallScheme(conf.SchemeManagers[id]); err != nil {
			rerr = err
			Logger.Warn("failed to reinstall issuer scheme: ", err)
		}
	}

	for id := range conf.DisabledRequestorSchemes {
		if err = conf.reinstallScheme(conf.RequestorSchemes[id]); err != nil {
			rerr = err
			Logger.Warn("failed to reinstall requestor scheme: ", err)
		}
	}

	return rerr
}

// Download downloads the issuers, credential types and public keys specified in set
// if the current Configuration does not already have them, and checks their authenticity
// using the scheme index.
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
		if err = conf.UpdateScheme(conf.SchemeManagers[id], downloaded); err != nil {
			return
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

func (conf *Configuration) AddPrivateKeyRing(ring PrivateKeyRing) error {
	if err := validatePrivateKeyRing(ring, conf); err != nil {
		return err
	}
	conf.PrivateKeys.(*privateKeyRingMerge).Add(ring)
	return nil
}

// PublicKey returns the specified public key, or nil if not present in the Configuration.
func (conf *Configuration) PublicKey(id IssuerIdentifier, counter uint) (*gabikeys.PublicKey, error) {
	// If we have not seen this issuer or key before in conf.publicKeys,
	// try to parse the public key folder; new keys might have been put there since we last parsed it
	if !conf.publicKeys.IsSet(PublicKeyIdentifier{id, counter}) {
		if err := conf.parseKeysFolder(id); err != nil {
			return nil, err
		}
	}
	return conf.publicKeys.Get(PublicKeyIdentifier{id, counter}), nil
}

// PublicKeyLatest returns the latest private key of the specified issuer.
func (conf *Configuration) PublicKeyLatest(id IssuerIdentifier) (*gabikeys.PublicKey, error) {
	indices, err := conf.PublicKeyIndices(id)
	if err != nil {
		return nil, err
	}
	if len(indices) == 0 {
		return nil, errors.New("no public keys found")
	}
	return conf.PublicKey(id, indices[len(indices)-1])
}

func (conf *Configuration) PublicKeyIndices(issuerid IssuerIdentifier) (i []uint, err error) {
	scheme := conf.SchemeManagers[issuerid.SchemeManagerIdentifier()]
	return matchKeyPattern(filepath.Join(scheme.path(), issuerid.Name(), "PublicKeys", "*"))
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
func (conf *Configuration) KeyshareServerPublicKey(schemeid SchemeManagerIdentifier, i int) (*rsa.PublicKey, error) {
	if _, contains := conf.kssPublicKeys[schemeid]; !contains {
		conf.kssPublicKeys[schemeid] = make(map[int]*rsa.PublicKey)
	}
	if _, contains := conf.kssPublicKeys[schemeid][i]; !contains {
		scheme := conf.SchemeManagers[schemeid]
		pkbts, err := ioutil.ReadFile(filepath.Join(scheme.path(), fmt.Sprintf("kss-%d.pem", i)))
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
		conf.kssPublicKeys[schemeid][i] = pk
	}
	return conf.kssPublicKeys[schemeid][i], nil
}

// IsInitialized indicates whether this instance has successfully been initialized.
func (conf *Configuration) IsInitialized() bool {
	return conf.initialized
}

func (conf *Configuration) ContainsAttributeType(attr AttributeTypeIdentifier) bool {
	_, contains := conf.AttributeTypes[attr]
	return contains && conf.ContainsCredentialType(attr.CredentialTypeIdentifier())
}

// ContainsCredentialType checks if the configuration contains the specified credential type.
func (conf *Configuration) ContainsCredentialType(cred CredentialTypeIdentifier) bool {
	return conf.SchemeManagers[cred.IssuerIdentifier().SchemeManagerIdentifier()] != nil &&
		conf.Issuers[cred.IssuerIdentifier()] != nil &&
		conf.CredentialTypes[cred] != nil
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

// parse $schememanager/$issuer/PublicKeys/$i.xml for $i = 1, ...
func (conf *Configuration) parseKeysFolder(issuerid IssuerIdentifier) error {
	scheme := conf.SchemeManagers[issuerid.SchemeManagerIdentifier()]
	pattern := filepath.Join(scheme.path(), issuerid.Name(), "PublicKeys", "*")
	files, err := filepath.Glob(pattern)
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
		relativepath, err := filepath.Rel(scheme.path(), file)
		if err != nil {
			return err
		}
		bts, found, err := conf.readSignedFile(scheme.index, scheme.path(), relativepath)
		if err != nil || !found {
			return err
		}
		pk, err := gabikeys.NewPublicKeyFromBytes(bts)
		if err != nil {
			return err
		}
		if pk.Counter != uint(i) {
			return errors.Errorf("Public key %s of issuer %s has wrong <Counter>", file, issuerid.String())
		}
		pk.Issuer = issuerid.String()
		conf.publicKeys.Set(PublicKeyIdentifier{issuerid, uint(i)}, pk)
	}

	return nil
}

func sorter(ints []uint) func(i, j int) bool {
	return func(i, j int) bool { return ints[i] < ints[j] }
}

func matchKeyPattern(pattern string) (ints []uint, err error) {
	files, err := filepath.Glob(pattern)
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

func (conf *Configuration) clear() {
	conf.SchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManager)
	conf.Issuers = make(map[IssuerIdentifier]*Issuer)
	conf.CredentialTypes = make(map[CredentialTypeIdentifier]*CredentialType)
	conf.AttributeTypes = make(map[AttributeTypeIdentifier]*AttributeType)
	conf.DisabledSchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManagerError)
	conf.RequestorSchemes = make(map[RequestorSchemeIdentifier]*RequestorScheme)
	conf.Requestors = make(map[string]*RequestorInfo)
	conf.IssueWizards = make(map[IssueWizardIdentifier]*IssueWizard)
	conf.DisabledRequestorSchemes = make(map[RequestorSchemeIdentifier]*SchemeManagerError)
	conf.kssPublicKeys = make(map[SchemeManagerIdentifier]map[int]*rsa.PublicKey)
	conf.publicKeys = concmap.New[PublicKeyIdentifier, *gabikeys.PublicKey]()
	conf.reverseHashes = make(map[string]CredentialTypeIdentifier)
	if conf.PrivateKeys == nil { // keep if already populated
		conf.PrivateKeys = &privateKeyRingMerge{}
	}
}

// Validation methods containing consistency checks on irma_configuration
func validateDemoPrefix(ts TranslatedString, langs []string) error {
	prefix := "Demo "
	for _, lang := range langs {
		if !strings.HasPrefix(map[string]string(ts)[lang], prefix) {
			return errors.Errorf("value in language %s is not prefixed with '%s'", lang, prefix)
		}
	}
	return nil
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
			for reqAttr := range credreq.Attributes {
				attrID := NewAttributeTypeIdentifier(credreq.CredentialTypeID.String() + "." + reqAttr)
				if !typ.ContainsAttribute(attrID) {
					missing.AttributeTypes[attrID] = struct{}{}
				}
			}

			// Check if all attributes from the configuration are present, unless they are marked as optional
			for _, attrtype := range typ.AttributeTypes {
				_, present := credreq.Attributes[attrtype.ID]
				if !present && !attrtype.RevocationAttribute && !attrtype.RandomBlind && !attrtype.IsOptional() {
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

// CheckSchemes verifies that all schemes occurring in the specified session request occur in this
// instance.
func (conf *Configuration) checkSchemes(session SessionRequest, missing *IrmaIdentifierSet) {
	for id := range session.Identifiers().SchemeManagers {
		scheme, contains := conf.SchemeManagers[id]
		if !contains || scheme.Status != SchemeManagerStatusValid {
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

func (conf *Configuration) validateIssuer(scheme *SchemeManager, issuer *Issuer, dir string) error {
	issuerid := issuer.Identifier()
	conf.validateTranslations(fmt.Sprintf("Issuer %s", issuerid.String()), issuer, issuer.Languages)
	// Check that the issuer has public keys
	pkpath := filepath.Join(scheme.path(), issuer.ID, "PublicKeys", "*")
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
	if scheme.ID != issuer.SchemeManagerID {
		return errors.Errorf("Issuer %s has wrong SchemeManager %s", issuerid.String(), issuer.SchemeManagerID)
	}
	if err = validateDemoPrefix(issuer.Name, issuer.Languages); scheme.Demo && err != nil {
		return errors.Errorf("Name of demo issuer %s invalid: %s", issuer.ID, err.Error())
	}
	if err = common.AssertPathExists(filepath.Join(dir, "logo.png")); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Issuer %s has no logo.png", issuerid.String()))
	}
	return nil
}

func (conf *Configuration) validateCredentialType(manager *SchemeManager, issuer *Issuer, cred *CredentialType, dir string) error {
	credid := cred.Identifier()
	conf.validateTranslations(fmt.Sprintf("Credential type %s", credid.String()), cred, cred.Languages)
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
	if err := validateDemoPrefix(cred.Name, cred.Languages); manager.Demo && err != nil {
		return errors.Errorf("Name of demo credential %s invalid: %s", credid.String(), err.Error())
	}

	for _, url := range cred.RevocationServers {
		if !manager.Demo && !strings.HasPrefix(url, "https://") {
			return errors.Errorf("Revocation server of %s does not use https://", credid.String())
		}
		if strings.HasSuffix(url, "/") {
			return errors.Errorf("Revocation server of %s should have no trailing /", credid.String())
		}
	}
	if err := common.AssertPathExists(filepath.Join(dir, "logo.png")); err != nil {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has no logo.png", credid.String()))
	}
	return conf.validateAttributes(cred)
}

func (conf *Configuration) validateAttributes(cred *CredentialType) error {
	name := cred.Identifier().String()
	indices := make(map[int]struct{})
	revocation := false
	count := len(cred.AttributeTypes)
	if count == 0 {
		return errors.Errorf("Credenial type %s has no attributes", name)
	}
	for i, attr := range cred.AttributeTypes {
		if !attr.RevocationAttribute {
			conf.validateTranslations(fmt.Sprintf("Attribute %s of credential type %s", attr.ID, cred.Identifier().String()), attr, cred.Languages)
		}
		index := i
		if attr.DisplayIndex != nil {
			index = *attr.DisplayIndex
		}
		if index >= count {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute displayIndex at attribute %d", name, i))
		}
		indices[index] = struct{}{}
		if attr.RevocationAttribute {
			cred.RevocationIndex = i
			revocation = true
		}
		if attr.RevocationAttribute && attr.RandomBlind {
			return errors.New("attribute cannot be both revocation attribute and randomblind attribute")
		}
	}
	if len(indices) != count {
		conf.Warnings = append(conf.Warnings, fmt.Sprintf("Credential type %s has invalid attribute ordering, check the displayIndex tags", name))
	}
	if revocation && !cred.RevocationSupported() {
		return errors.New("revocation attribute found but no RevocationServers configured")
	}
	if !revocation && cred.RevocationSupported() {
		return errors.New("RevocationServers configured but no revocation attribute found")
	}
	return nil
}

// validateTranslations checks for each member of the interface o that is of type TranslatedString
// that it contains all necessary translations.
func (conf *Configuration) validateTranslations(file string, o interface{}, langs []string) {
	v := reflect.ValueOf(o)

	// Dereference in case of pointer or interface
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name
		translatedString := TranslatedString{}
		if field.Type() != reflect.TypeOf(translatedString) && field.Type() != reflect.TypeOf(&translatedString) {
			continue
		}
		var val TranslatedString
		if field.Type() == reflect.TypeOf(&translatedString) {
			tmp := field.Interface().(*TranslatedString)
			if tmp == nil {
				return
			}
			val = *tmp
		} else {
			val = field.Interface().(TranslatedString)
		}

		if len(val) == 0 {
			conf.Warnings = append(conf.Warnings, fmt.Sprintf("%s has empty <%s> tag", file, name))
		}

		// assuming that translations also never should be empty
		if l := val.validate(langs); len(l) > 0 {
			for _, invalidLang := range l {
				conf.Warnings = append(conf.Warnings, fmt.Sprintf("%s misses %s translation in <%s> tag", file, invalidLang, name))
			}
		}
	}
}

func (conf *Configuration) join(other *Configuration) {
	for key, val := range other.SchemeManagers {
		conf.SchemeManagers[key] = val
	}
	for key, val := range other.DisabledSchemeManagers {
		conf.DisabledSchemeManagers[key] = val
	}
	for key, val := range other.Issuers {
		conf.Issuers[key] = val
	}
	for key, val := range other.CredentialTypes {
		conf.CredentialTypes[key] = val
	}
	for key, val := range other.reverseHashes {
		conf.reverseHashes[key] = val
	}
	for key, val := range other.AttributeTypes {
		conf.AttributeTypes[key] = val
	}
	for key, val := range other.kssPublicKeys {
		conf.kssPublicKeys[key] = val
	}
	for key, val := range other.RequestorSchemes {
		conf.RequestorSchemes[key] = val
	}
	for key, val := range other.Requestors {
		conf.Requestors[key] = val
	}
	for key, val := range other.IssueWizards {
		conf.IssueWizards[key] = val
	}
	for key, val := range other.DisabledRequestorSchemes {
		conf.DisabledRequestorSchemes[key] = val
	}
	other.publicKeys.Iterate(func(key PublicKeyIdentifier, val *gabikeys.PublicKey) {
		conf.publicKeys.Set(key, val)
	})

	conf.CallListeners()
}

func (e *UnknownIdentifierError) Error() string {
	return "Unknown identifiers: " + e.Missing.String()
}

func (e *RequiredAttributeMissingError) Error() string {
	return "Required attributes are missing: " + e.Missing.String()
}

// DefaultDataPath returns the default storage path for IRMA, using XDG Base Directory Specification
// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html:
//   - %LOCALAPPDATA% (i.e. C:\Users\$user\AppData\Local) if on Windows,
//   - $XDG_DATA_HOME if set, otherwise $HOME/.local/share
//   - $XDG_DATA_DIRS if set, otherwise /usr/local/share/ and /usr/share/
//   - then the OSes temp dir (os.TempDir()),
//
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
	if err := common.EnsureDirectoryExists(p); err != nil {
		return ""
	}
	return p
}

func firstExistingPath(paths []string) string {
	for _, p := range paths {
		if err := common.EnsureDirectoryExists(p); err == nil {
			return p
		}
	}
	return ""
}

func (conf *Configuration) CallListeners() {
	for _, listener := range conf.UpdateListeners {
		listener(conf)
	}
}
