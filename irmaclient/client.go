package irmaclient

import (
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

// This file contains most methods of the Client (c.f. session.go
// and updates.go).
//
// Clients are the main entry point into this package for the user of this package.
// The Client struct:
// - (De)serializes credentials and keyshare server information
// from storage, as well as logs of earlier IRMA sessions
// - it provides access to the attributes and all related information of its credentials,
// - it is the starting point for new IRMA sessions;
// - and it computes some of the messages in the client side of the IRMA protocol.
//
// The storage of credentials is split up in several parts:
//
// - The CL-signature of each credential is stored separately, so that we can
// load it on demand (i.e., during an IRMA session), instead of immediately
// at initialization.
//
// - The attributes of all credentials are stored together, as they all
// immediately need to be available anyway.
//
// - The secret key (the zeroth attribute of every credential), being the same
// across all credentials, is stored only once in a separate file (storing this
// in multiple places would be bad).

type Client struct {
	// Stuff we manage on disk
	secretkey        *secretKey
	attributes       map[irma.CredentialTypeIdentifier][]*irma.AttributeList
	credentialsCache map[irma.CredentialTypeIdentifier]map[int]*credential
	keyshareServers  map[irma.SchemeManagerIdentifier]*keyshareServer
	updates          []update

	lookup map[string]*credLookup

	// Where we store/load it to/from
	storage storage
	// Legacy storage needed when client has not updated to the new storage yet
	fileStorage fileStorage

	// Other state
	Preferences           Preferences
	Configuration         *irma.Configuration
	irmaConfigurationPath string
	handler               ClientHandler

	jobs       chan func()   // queue of jobs to run
	jobsPause  chan struct{} // sending pauses background jobs
	jobsPaused bool

	credMutex sync.Mutex
}

// TODO: consider if we should save irmamobile preferences here, because they would automatically
// be part of any backup and syncing solution we implement at a later time
type Preferences struct {
	DeveloperMode bool
}

var defaultPreferences = Preferences{
	DeveloperMode: false,
}

// KeyshareHandler is used for asking the user for his email address and PIN,
// for enrolling at a keyshare server.
type KeyshareHandler interface {
	EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error)
	EnrollmentSuccess(manager irma.SchemeManagerIdentifier)
}

type ChangePinHandler interface {
	ChangePinFailure(manager irma.SchemeManagerIdentifier, err error)
	ChangePinSuccess(manager irma.SchemeManagerIdentifier)
	ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int)
	ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int)
}

// ClientHandler informs the user that the configuration or the list of attributes
// that this client uses has been updated.
type ClientHandler interface {
	KeyshareHandler
	ChangePinHandler

	UpdateConfiguration(new *irma.IrmaIdentifierSet)
	UpdateAttributes()
	Revoked(cred *irma.CredentialIdentifier)
	ReportError(err error)
}

type credLookup struct {
	id      irma.CredentialTypeIdentifier
	counter int
}

type credCandidateSet [][]*credCandidate

type credCandidate irma.CredentialIdentifier

type DisclosureCandidate struct {
	*irma.AttributeIdentifier
	Expired      bool
	Revoked      bool
	NotRevokable bool
}

type DisclosureCandidates []*DisclosureCandidate

type secretKey struct {
	Key *big.Int
}

// New creates a new Client that uses the directory
// specified by storagePath for (de)serializing itself. irmaConfigurationPath
// is the path to a (possibly readonly) folder containing irma_configuration;
// and handler is used for informing the user of new stuff, and when a
// enrollment to a keyshare server needs to happen.
// The client returned by this function has been fully deserialized
// and is ready for use.
//
// NOTE: It is the responsibility of the caller that there exists a (properly
// protected) directory at storagePath!
func New(
	storagePath string,
	irmaConfigurationPath string,
	handler ClientHandler,
) (*Client, error) {
	var err error
	if err = common.AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err = common.AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}

	client := &Client{
		credentialsCache:      make(map[irma.CredentialTypeIdentifier]map[int]*credential),
		keyshareServers:       make(map[irma.SchemeManagerIdentifier]*keyshareServer),
		attributes:            make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList),
		irmaConfigurationPath: irmaConfigurationPath,
		handler:               handler,
	}

	client.Configuration, err = irma.NewConfiguration(
		filepath.Join(storagePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: irmaConfigurationPath},
	)
	if err != nil {
		return nil, err
	}

	schemeMgrErr := client.Configuration.ParseOrRestoreFolder()
	// If schemMgrErr is of type SchemeManagerError, we continue and
	// return it at the end; otherwise bail out now
	_, isSchemeMgrErr := schemeMgrErr.(*irma.SchemeManagerError)
	if schemeMgrErr != nil && !isSchemeMgrErr {
		return nil, schemeMgrErr
	}

	// Ensure storage path exists, and populate it with necessary files
	client.storage = storage{storagePath: storagePath, Configuration: client.Configuration}
	if err = client.storage.Open(); err != nil {
		return nil, err
	}
	// Legacy storage does not need ensuring existence
	client.fileStorage = fileStorage{storagePath: storagePath, Configuration: client.Configuration}

	if client.Preferences, err = client.storage.LoadPreferences(); err != nil {
		return nil, err
	}
	client.applyPreferences()

	// Perform new update functions from clientUpdates, if any
	if err = client.update(); err != nil {
		return nil, err
	}

	// Load our stuff
	if client.secretkey, err = client.storage.LoadSecretKey(); err != nil {
		return nil, err
	}
	if client.attributes, err = client.storage.LoadAttributes(); err != nil {
		return nil, err
	}
	if client.keyshareServers, err = client.storage.LoadKeyshareServers(); err != nil {
		return nil, err
	}

	if len(client.UnenrolledSchemeManagers()) > 1 {
		return nil, errors.New("Too many keyshare servers")
	}

	client.lookup = map[string]*credLookup{}
	for _, attrlistlist := range client.attributes {
		for i, attrlist := range attrlistlist {
			client.lookup[attrlist.Hash()] = &credLookup{id: attrlist.CredentialType().Identifier(), counter: i}
		}
	}

	client.jobs = make(chan func(), 100)
	client.initRevocation()
	client.StartJobs()

	return client, schemeMgrErr
}

func (client *Client) Close() error {
	return client.storage.Close()
}

func (client *Client) nonrevCredPrepareCache(credid irma.CredentialTypeIdentifier, index int) error {
	irma.Logger.WithFields(logrus.Fields{"credid": credid, "index": index}).Debug("Preparing cache")
	cred, err := client.credential(credid, index)
	if err != nil {
		return err
	}
	return cred.NonrevPrepareCache()
}

func (client *Client) reportError(err error) {
	irma.Logger.Error(err)
	client.handler.ReportError(err)
}

// StartJobs performs scheduled background jobs in separate goroutines.
// Pause pending jobs with PauseJobs().
func (client *Client) StartJobs() {
	irma.Logger.Debug("starting jobs")
	if client.jobsPause != nil {
		irma.Logger.Debug("already running")
		return
	}

	client.jobsPaused = false
	client.jobsPause = make(chan struct{})
	go func() {
		for {
			select {
			case <-client.jobsPause:
				client.jobsPause = nil
				irma.Logger.Debug("jobs stopped")
				return
			case job := <-client.jobs:
				irma.Logger.Debug("doing job")
				job()
				irma.Logger.Debug("job done")
			}
		}
	}()
}

// PauseJobs pauses background job processing.
func (client *Client) PauseJobs() {
	irma.Logger.Debug("pausing jobs")
	if client.jobsPaused {
		irma.Logger.Debug("already paused")
		return
	}
	client.jobsPaused = true
	close(client.jobsPause)
}

// CredentialInfoList returns a list of information of all contained credentials.
func (client *Client) CredentialInfoList() irma.CredentialInfoList {
	list := irma.CredentialInfoList([]*irma.CredentialInfo{})

	for _, attrlistlist := range client.attributes {
		for _, attrlist := range attrlistlist {
			info := attrlist.Info()
			if info == nil {
				continue
			}
			list = append(list, info)
		}
	}

	return list
}

// addCredential adds the specified credential to the Client, saving its signature
// imediately, and optionally cm.attributes as well.
func (client *Client) addCredential(cred *credential) (err error) {
	id := irma.NewCredentialTypeIdentifier("")
	if cred.CredentialType() != nil {
		id = cred.CredentialType().Identifier()
	}

	// If we receive a duplicate credential it should overwrite the previous one; remove it first
	// (it makes no sense to possess duplicate credentials, but the new signature might contain new
	// functionality such as a nonrevocation witness, so it does not suffice to just return here)
	index := -1
	for _, attrlistlist := range client.attributes {
		for i, attrs := range attrlistlist {
			if attrs.Hash() == cred.attrs.Hash() {
				index = i
				break
			}
		}
	}
	if index != -1 {
		if err = client.remove(id, index, false); err != nil {
			return err
		}
	}

	// If this is a singleton credential type, ensure we have at most one by removing any previous instance
	// If a credential already exists with exactly the same attribute values (except metadata), delete the previous credential
	if !id.Empty() {
		if cred.CredentialType().IsSingleton {
			for len(client.attrs(id)) != 0 {
				if err = client.remove(id, 0, false); err != nil {
					return
				}
			}
		}

		for i := len(client.attrs(id)) - 1; i >= 0; i-- { // Go backwards through array because remove manipulates it
			if client.attrs(id)[i].EqualsExceptMetadata(cred.attrs) {
				if err = client.remove(id, i, false); err != nil {
					return
				}
			}
		}
	}

	// Append the new cred to our attributes and credentials
	client.attributes[id] = append(client.attrs(id), cred.attrs)
	if !id.Empty() {
		if _, exists := client.credentialsCache[id]; !exists {
			client.credentialsCache[id] = make(map[int]*credential)
		}
		counter := len(client.attributes[id]) - 1
		client.credentialsCache[id][counter] = cred
		client.lookup[cred.attrs.Hash()] = &credLookup{id: id, counter: counter}
	}

	return client.storage.Transaction(func(tx *transaction) error {
		if err = client.storage.TxStoreSignature(tx, cred); err != nil {
			return err
		}
		return client.storage.TxStoreAttributes(tx, id, client.attributes[id])
	})
}

func generateSecretKey() (*secretKey, error) {
	return &secretKey{
		Key: common.RandomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[1024].Lm))),
	}, nil
}

// Removal methods

func (client *Client) remove(id irma.CredentialTypeIdentifier, index int, storeLog bool) error {
	// Remove attributes
	list, exists := client.attributes[id]
	if !exists || index >= len(list) {
		return errors.Errorf("Can't remove credential %s-%d: no such credential", id.String(), index)
	}
	attrs := list[index]
	client.attributes[id] = append(list[:index], list[index+1:]...)

	removed := map[irma.CredentialTypeIdentifier][]irma.TranslatedString{}
	removed[id] = attrs.Strings()

	err := client.storage.Transaction(func(tx *transaction) error {
		if err := client.storage.TxDeleteSignature(tx, attrs); err != nil {
			return err
		}
		if err := client.storage.TxStoreAttributes(tx, id, client.attributes[id]); err != nil {
			return err
		}
		if storeLog {
			return client.storage.TxAddLogEntry(tx, &LogEntry{
				Type:    ActionRemoval,
				Time:    irma.Timestamp(time.Now()),
				Removed: removed,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Remove credential from cache
	if creds, exists := client.credentialsCache[id]; exists {
		if _, exists := creds[index]; exists {
			delete(creds, index)
			client.credentialsCache[id] = creds
		}
	}
	delete(client.lookup, attrs.Hash())
	for i, attrs := range client.attributes[id] {
		client.lookup[attrs.Hash()].counter = i
	}
	return nil
}

// RemoveCredential removes the specified credential if that is allowed.
func (client *Client) RemoveCredential(id irma.CredentialTypeIdentifier, index int) error {
	if client.Configuration.CredentialTypes[id].DisallowDelete {
		return errors.Errorf("configuration does not allow removal of credential type %s", id.String())
	}
	return client.remove(id, index, true)
}

// RemoveCredentialByHash removes the specified credential.
func (client *Client) RemoveCredentialByHash(hash string) error {
	cred, index, err := client.credentialByHash(hash)
	if err != nil {
		return err
	}
	return client.RemoveCredential(cred.CredentialType().Identifier(), index)
}

// Removes all attributes, signatures, logs and userdata
// Includes the user's secret key, keyshare servers and preferences/updates
// A fresh secret key is installed.
func (client *Client) RemoveStorage() error {
	var err error

	// Remove data from memory
	client.attributes = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	client.keyshareServers = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	client.credentialsCache = make(map[irma.CredentialTypeIdentifier]map[int]*credential)
	client.lookup = make(map[string]*credLookup)

	if err = client.storage.DeleteAll(); err != nil {
		return err
	}
	if err = client.fileStorage.DeleteAll(); err != nil {
		return err
	}

	// Client assumes there is always a secret key, so we have to load a new one
	client.secretkey, err = client.storage.LoadSecretKey()
	if err != nil {
		return err
	}

	// TODO: do we consider this setting as user data?
	if client.Preferences, err = client.storage.LoadPreferences(); err != nil {
		return err
	}
	client.applyPreferences()

	return nil
}

// Attribute and credential getter methods

// attrs returns cm.attributes[id], initializing it to an empty slice if neccesary
func (client *Client) attrs(id irma.CredentialTypeIdentifier) []*irma.AttributeList {
	list, exists := client.attributes[id]
	if !exists {
		list = make([]*irma.AttributeList, 0, 1)
		client.attributes[id] = list
	}
	return list
}

// creds returns cm.credentials[id], initializing it to an empty map if neccesary
func (client *Client) creds(id irma.CredentialTypeIdentifier) map[int]*credential {
	list, exists := client.credentialsCache[id]
	if !exists {
		list = make(map[int]*credential)
		client.credentialsCache[id] = list
	}
	return list
}

// Attributes returns the attribute list of the requested credential, or nil if we do not have it.
func (client *Client) Attributes(id irma.CredentialTypeIdentifier, counter int) (attributes *irma.AttributeList) {
	list := client.attrs(id)
	if len(list) <= counter {
		return
	}
	return list[counter]
}

func (client *Client) attributesByHash(hash string) (*irma.AttributeList, int) {
	lookup, present := client.lookup[hash]
	if !present {
		return nil, 0
	}
	return client.attributes[lookup.id][lookup.counter], lookup.counter
}

func (client *Client) credentialByHash(hash string) (*credential, int, error) {
	attrs, index := client.attributesByHash(hash)
	if attrs != nil {
		cred, err := client.credential(attrs.CredentialType().Identifier(), index)
		return cred, index, err
	}
	return nil, 0, nil
}

func (client *Client) credentialByID(id irma.CredentialIdentifier) (*credential, error) {
	cred, _, err := client.credentialByHash(id.Hash)
	return cred, err
}

// credential returns the requested credential, or nil if we do not have it.
func (client *Client) credential(id irma.CredentialTypeIdentifier, counter int) (cred *credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during New(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	if _, exists := client.creds(id)[counter]; !exists {
		attrs := client.Attributes(id, counter)
		if attrs == nil { // We do not have the requested cred
			return
		}
		sig, witness, err := client.storage.LoadSignature(attrs)
		if err != nil {
			return nil, err
		}
		if sig == nil {
			err = errors.New("signature file not found")
			return nil, err
		}
		pk, err := attrs.PublicKey()
		if err != nil {
			return nil, err
		}
		if pk == nil {
			return nil, errors.New("unknown public key")
		}
		cred, err := newCredential(&gabi.Credential{
			Attributes:           append([]*big.Int{client.secretkey.Key}, attrs.Ints...),
			Signature:            sig,
			NonRevocationWitness: witness,
			Pk:                   pk,
		}, attrs, client.Configuration)
		if err != nil {
			return nil, err
		}
		client.credentialsCache[id][counter] = cred
	}

	return client.credentialsCache[id][counter], nil
}

// Methods used in the IRMA protocol

// credCandidates returns a list containing a list of candidate credential instances for each item
// in the conjunction. (A credential instance from the client is a candidate it it contains
// attributes required in this conjunction). If one credential type occurs multiple times in the
// conjunction it is not added twice.
func (client *Client) credCandidates(base *irma.BaseRequest, con irma.AttributeCon) (credCandidateSet, bool, error) {
	var candidates [][]*credCandidate
	satisfiable := true

	for _, credtype := range con.CredentialTypes() {
		attrlistlist := client.attributes[credtype]
		var c []*credCandidate
		haveUsableCred := false
		for _, attrlist := range attrlistlist {
			satisfies, usable := client.satisfiesCon(base, attrlist, con)
			if satisfies { // add it to the list, even if they are unusable
				c = append(c, &credCandidate{Type: credtype, Hash: attrlist.Hash()})
			}
			if usable { // having one usable credential will do
				haveUsableCred = true
			}
		}
		if !haveUsableCred {
			// if for one of the credential types in this conjunction we don't have candidates,
			// then the entire conjunction is unsatisfiable
			satisfiable = false
		}
		if len(c) == 0 {
			// No acceptable credentials found, add "empty" credential (i.e. without hash) to the candidates
			c = append(c, &credCandidate{Type: credtype})
			satisfiable = false
		}
		candidates = append(candidates, c)
	}
	return candidates, satisfiable, nil
}

// satsifiesCon returns:
//  - if the attrs can satsify the conjunction (as long as it is usable),
//  - if the attrs are usable (they are not expired, or revoked, or not revocation-aware while
//    a nonrevocation proof is required).
func (client *Client) satisfiesCon(base *irma.BaseRequest, attrs *irma.AttributeList, con irma.AttributeCon) (bool, bool) {
	var credfound bool
	credtype := attrs.CredentialType().Identifier()
	for _, attr := range con {
		if attr.Type.CredentialTypeIdentifier() != credtype {
			continue
		}
		credfound = true
		if !attr.Satisfy(attr.Type, attrs.UntranslatedAttribute(attr.Type)) {
			// Using attributes out of more than one instance of a credential type to satisfy
			// a single con is not allowed, so if any one of the attributes of this instance does
			// not have the appropriate value, then this entire credential cannot be used
			// for this con.
			return false, false
		}
	}
	if !credfound {
		return false, false
	}
	cred, _, _ := client.credentialByHash(attrs.Hash())
	usable := !attrs.Revoked && attrs.IsValid() && (!base.RequestsRevocation(credtype) || cred.NonRevocationWitness != nil)
	return true, usable
}

func (set credCandidateSet) multiply(candidates []*credCandidate) credCandidateSet {
	result := make(credCandidateSet, 0, len(set)*len(candidates))
	for _, cred := range candidates {
		for _, toDisclose := range set {
			result = append(result, append(toDisclose, cred))
		}
	}
	return result
}

func (set credCandidateSet) expand(client *Client, base *irma.BaseRequest, con irma.AttributeCon) []DisclosureCandidates {
	var result []DisclosureCandidates

	for _, s := range set {
		var candidateSet []*DisclosureCandidate
		for _, credopt := range s {
			for _, attr := range con {
				if attr.Type.CredentialTypeIdentifier() != credopt.Type {
					continue
				}
				attropt := &DisclosureCandidate{
					AttributeIdentifier: &irma.AttributeIdentifier{
						Type:           attr.Type,
						CredentialHash: credopt.Hash,
					},
				}
				if credopt.Present() {
					attrlist, _ := client.attributesByHash(credopt.Hash)
					cred, _, _ := client.credentialByHash(credopt.Hash)
					attropt.Expired = !attrlist.IsValid()
					attropt.Revoked = attrlist.Revoked
					attropt.NotRevokable = cred.NonRevocationWitness == nil && base.RequestsRevocation(credopt.Type)
				}
				candidateSet = append(candidateSet, attropt)
			}
		}
		result = append(result, candidateSet)
	}

	return result
}

func cartesianProduct(candidates [][]*credCandidate) credCandidateSet {
	set := credCandidateSet{[]*credCandidate{}} // Unit element for this multiplication
	for _, c := range candidates {
		set = set.multiply(c)
	}
	return set
}

// candidatesDisCon returns attributes present in this client that satisfy the specified attribute
// disjunction. It returns a list of candidate attribute sets, each of which would satisfy the
// specified disjunction.
func (client *Client) candidatesDisCon(base *irma.BaseRequest, discon irma.AttributeDisCon) (
	candidates []DisclosureCandidates, satisfiable bool, err error,
) {
	candidates = []DisclosureCandidates{}

	for _, con := range discon {
		if len(con) == 0 {
			// An empty conjunction means the containing disjunction is optional
			// so it is satisfied by sending no attributes
			candidates = append(candidates, []*DisclosureCandidate{})
			satisfiable = true
			continue
		}

		// Build a list containing, for each attribute in this conjunction, a list of credential
		// instances containing the attribute. Writing schematically a sample conjunction of three
		// attribute types as [ a.a.a.a, a.a.a.b, a.a.b.x ], we map this to:
		// [ [ a.a.a #1, a.a.a #2] , [ a.a.b #1 ] ]
		// assuming the client has 2 instances of a.a.a and 1 instance of a.a.b.
		c, conSatisfiable, err := client.credCandidates(base, con)
		if err != nil {
			return nil, false, err
		}
		if conSatisfiable {
			satisfiable = true
		}

		// The cartesian product of the list of lists constructed above results in a list of which
		// each item is a list of credentials containing attributes that together will satisfy the
		// current conjunction
		// [ [ a.a.a #1, a.a.b #1 ], [ a.a.a #2, a.a.b #1 ] ]
		c = cartesianProduct(c)

		// Expand each credential instance to those attribute instances within it that the con
		// is asking for, resulting in attribute sets each of which would satisfy the conjunction,
		// and therefore the containing disjunction
		// [ [ a.a.a.a #1, a.a.a.b #1, a.a.b.x #1 ], [ a.a.a.a #2, a.a.a.b #2, a.a.b.x #1 ] ]
		candidates = append(candidates, c.expand(client, base, con)...)
	}

	return
}

// Candidates returns a list of options for the user to choose from,
// given a session request and the credentials currently in storage.
func (client *Client) Candidates(request irma.SessionRequest) (
	candidates [][]DisclosureCandidates, satisfiable bool, err error,
) {
	condiscon := request.Disclosure().Disclose
	candidates = make([][]DisclosureCandidates, len(condiscon))

	satisfiable = true
	client.credMutex.Lock()
	defer client.credMutex.Unlock()
	for i, discon := range condiscon {
		cands, disconSatisfiable, err := client.candidatesDisCon(request.Base(), discon)
		if err != nil {
			return nil, false, err
		}
		if !disconSatisfiable {
			satisfiable = false
		}
		candidates[i] = cands
	}
	return
}

// attributeGroup points to a credential and some of its attributes which are to be disclosed
type attributeGroup struct {
	cred  irma.CredentialIdentifier
	attrs []int
}

// Given the user's choice of attributes to be disclosed, group them per credential out of which they
// are to be disclosed
func (client *Client) groupCredentials(choice *irma.DisclosureChoice) (
	[]attributeGroup, irma.DisclosedAttributeIndices, error,
) {
	if choice == nil || choice.Attributes == nil {
		return []attributeGroup{}, irma.DisclosedAttributeIndices{}, nil
	}

	// maps an irma.CredentialIdentifier to its index in the final ProofList
	credIndices := make(map[irma.CredentialIdentifier]int)
	todisclose := make([]attributeGroup, 0, len(choice.Attributes))
	attributeIndices := make(irma.DisclosedAttributeIndices, len(choice.Attributes))
	for i, attributeset := range choice.Attributes {
		attributeIndices[i] = []*irma.DisclosedAttributeIndex{}
		for _, attribute := range attributeset {
			var credIndex int
			ici := attribute.CredentialIdentifier()
			if _, present := credIndices[ici]; !present {
				credIndex = len(todisclose)
				credIndices[ici] = credIndex
				todisclose = append(todisclose, attributeGroup{
					cred: ici, attrs: []int{1}, // Always disclose metadata
				})
			} else {
				credIndex = credIndices[ici]
			}

			identifier := attribute.Type
			if identifier.IsCredential() {
				attributeIndices[i] = append(attributeIndices[i], &irma.DisclosedAttributeIndex{CredentialIndex: credIndex, AttributeIndex: 1, Identifier: ici})
				continue // In this case we only disclose the metadata attribute, which is already handled above
			}

			attrIndex, err := client.Configuration.CredentialTypes[identifier.CredentialTypeIdentifier()].IndexOf(identifier)
			if err != nil {
				return nil, nil, err
			}
			// These attribute indices will be used in the []*big.Int at gabi.credential.Attributes,
			// which doesn't know about the secret key and metadata attribute, so +2
			attributeIndices[i] = append(attributeIndices[i], &irma.DisclosedAttributeIndex{CredentialIndex: credIndex, AttributeIndex: attrIndex + 2, Identifier: ici})
			todisclose[credIndex].attrs = append(todisclose[credIndex].attrs, attrIndex+2)
		}
	}

	return todisclose, attributeIndices, nil
}

// ProofBuilders constructs a list of proof builders for the specified attribute choice.
func (client *Client) ProofBuilders(choice *irma.DisclosureChoice, request irma.SessionRequest,
) (gabi.ProofBuilderList, irma.DisclosedAttributeIndices, *atum.Timestamp, error) {
	todisclose, attributeIndices, err := client.groupCredentials(choice)
	if err != nil {
		return nil, nil, nil, err
	}

	var builders gabi.ProofBuilderList
	var builder gabi.ProofBuilder
	for _, grp := range todisclose {
		cred, err := client.credentialByID(grp.cred)
		if err != nil {
			return nil, nil, nil, err
		}
		if cred.attrs.Revoked {
			return nil, nil, nil, revocation.ErrorRevoked
		}
		nonrev := request.Base().RequestsRevocation(cred.CredentialType().Identifier())
		builder, err = cred.CreateDisclosureProofBuilder(grp.attrs, nonrev)
		if err != nil {
			return nil, nil, nil, err
		}
		builders = append(builders, builder)
	}

	var timestamp *atum.Timestamp
	if r, ok := request.(*irma.SignatureRequest); ok {
		var sigs []*big.Int
		var disclosed [][]*big.Int
		var s *big.Int
		var d []*big.Int
		for _, builder := range builders {
			s, d = builder.(*gabi.DisclosureProofBuilder).TimestampRequestContributions()
			sigs = append(sigs, s)
			disclosed = append(disclosed, d)
		}
		timestamp, err = irma.GetTimestamp(r.Message, sigs, disclosed, client.Configuration)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return builders, attributeIndices, timestamp, nil
}

// Proofs computes disclosure proofs containing the attributes specified by choice.
func (client *Client) Proofs(choice *irma.DisclosureChoice, request irma.SessionRequest) (*irma.Disclosure, *atum.Timestamp, error) {
	builders, choices, timestamp, err := client.ProofBuilders(choice, request)
	if err != nil {
		return nil, nil, err
	}

	_, issig := request.(*irma.SignatureRequest)
	return &irma.Disclosure{
		Proofs:  builders.BuildProofList(request.Base().GetContext(), request.GetNonce(timestamp), issig),
		Indices: choices,
	}, timestamp, nil
}

// generateIssuerProofNonce generates a nonce which the issuer must use in its gabi.ProofS.
func generateIssuerProofNonce() (*big.Int, error) {
	return common.RandomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[4096].Lstatzk))), nil
}

// IssuanceProofBuilders constructs a list of proof builders in the issuance protocol
// for the future credentials as well as possibly any disclosed attributes, and generates
// a nonce against which the issuer's proof of knowledge must verify.
func (client *Client) IssuanceProofBuilders(request *irma.IssuanceRequest, choice *irma.DisclosureChoice,
) (gabi.ProofBuilderList, irma.DisclosedAttributeIndices, *big.Int, error) {
	issuerProofNonce, err := generateIssuerProofNonce()
	if err != nil {
		return nil, nil, nil, err
	}
	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{})
	for _, futurecred := range request.Credentials {
		var pk *gabi.PublicKey
		pk, err = client.Configuration.PublicKey(futurecred.CredentialTypeID.IssuerIdentifier(), futurecred.KeyCounter)
		if err != nil {
			return nil, nil, nil, err
		}
		credBuilder := gabi.NewCredentialBuilder(
			pk, request.GetContext(), client.secretkey.Key, issuerProofNonce)
		builders = append(builders, credBuilder)
	}

	disclosures, choices, _, err := client.ProofBuilders(choice, request)
	if err != nil {
		return nil, nil, nil, err
	}
	builders = append(disclosures, builders...)
	return builders, choices, issuerProofNonce, nil
}

// IssueCommitments computes issuance commitments, along with disclosure proofs specified by choice,
// and also returns the credential builders which will become the new credentials upon combination with the issuer's signature.
func (client *Client) IssueCommitments(request *irma.IssuanceRequest, choice *irma.DisclosureChoice,
) (*irma.IssueCommitmentMessage, gabi.ProofBuilderList, error) {
	builders, choices, issuerProofNonce, err := client.IssuanceProofBuilders(request, choice)
	if err != nil {
		return nil, nil, err
	}
	return &irma.IssueCommitmentMessage{
		IssueCommitmentMessage: &gabi.IssueCommitmentMessage{
			Proofs: builders.BuildProofList(request.GetContext(), request.GetNonce(nil), false),
			Nonce2: issuerProofNonce,
		},
		Indices: choices,
	}, builders, nil
}

// ConstructCredentials constructs and saves new credentials using the specified issuance signature messages
// and credential builders.
func (client *Client) ConstructCredentials(msg []*gabi.IssueSignatureMessage, request *irma.IssuanceRequest, builders gabi.ProofBuilderList) error {
	if len(msg) > len(builders) {
		return errors.New("Received unexpected amount of signatures")
	}

	// First collect all credentials in a slice, so that if one of them induces an error,
	// we save none of them to fail the session cleanly
	gabicreds := []*gabi.Credential{}
	offset := 0
	for i, builder := range builders {
		credbuilder, ok := builder.(*gabi.CredentialBuilder)
		if !ok { // Skip builders of disclosure proofs
			offset++
			continue
		}
		sig := msg[i-offset]

		var nonrevAttr *big.Int
		if sig.NonRevocationWitness != nil {
			nonrevAttr = sig.NonRevocationWitness.E
		}
		issuedAt := time.Now()
		attrs, err := request.Credentials[i-offset].AttributeList(
			client.Configuration,
			irma.GetMetadataVersion(request.Base().ProtocolVersion),
			nonrevAttr,
			issuedAt,
		)
		if err != nil {
			return err
		}
		cred, err := credbuilder.ConstructCredential(sig, attrs.Ints)
		if err != nil {
			return err
		}
		gabicreds = append(gabicreds, cred)
	}

	for _, gabicred := range gabicreds {
		attrs := irma.NewAttributeListFromInts(gabicred.Attributes[1:], client.Configuration)
		newcred, err := newCredential(gabicred, attrs, client.Configuration)
		if err != nil {
			return err
		}
		if err = client.addCredential(newcred); err != nil {
			return err
		}
	}

	return nil
}

// Keyshare server handling

func (client *Client) genSchemeManagersList(enrolled bool) []irma.SchemeManagerIdentifier {
	list := []irma.SchemeManagerIdentifier{}
	for name, manager := range client.Configuration.SchemeManagers {
		if _, contains := client.keyshareServers[name]; manager.Distributed() && contains == enrolled {
			list = append(list, manager.Identifier())
		}
	}
	return list
}

func (client *Client) UnenrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.genSchemeManagersList(false)
}

func (client *Client) EnrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.genSchemeManagersList(true)
}

// KeyshareEnroll attempts to enroll at the keyshare server of the specified scheme manager.
func (client *Client) KeyshareEnroll(manager irma.SchemeManagerIdentifier, email *string, pin string, lang string) {
	go func() {
		err := client.keyshareEnrollWorker(manager, email, pin, lang)
		if err != nil {
			client.handler.EnrollmentFailure(manager, err)
		}
	}()
}

func (client *Client) keyshareEnrollWorker(managerID irma.SchemeManagerIdentifier, email *string, pin string, lang string) error {
	manager, ok := client.Configuration.SchemeManagers[managerID]
	if !ok {
		return errors.New("Unknown scheme manager")
	}
	if len(manager.KeyshareServer) == 0 {
		return errors.New("Scheme manager has no keyshare server")
	}
	if len(pin) < 5 {
		return errors.New("PIN too short, must be at least 5 characters")
	}

	transport := irma.NewHTTPTransport(manager.KeyshareServer, !client.Preferences.DeveloperMode)
	kss, err := newKeyshareServer(managerID)
	if err != nil {
		return err
	}
	message := keyshareEnrollment{
		Email:    email,
		Pin:      kss.HashedPin(pin),
		Language: lang,
	}

	qr := &irma.Qr{}
	err = transport.Post("client/register", qr, message)
	if err != nil {
		return err
	}

	// We add the new keyshare server to the client here, without saving it to disk,
	// and start the issuance session for the keyshare server login attribute -
	// keyshare.go needs the relevant keyshare server to be present in the client.
	// If the session succeeds or fails, the keyshare server is stored to disk or
	// removed from the client by the keyshareEnrollmentHandler.
	client.keyshareServers[managerID] = kss
	client.newQrSession(qr, &keyshareEnrollmentHandler{
		client: client,
		pin:    pin,
		kss:    kss,
	})

	return nil
}

// KeyshareVerifyPin verifies the specified PIN at the keyshare server, returning if it succeeded;
// if not, how many tries are left, or for how long the user is blocked. If an error is returned
// it is of type *irma.SessionError.
func (client *Client) KeyshareVerifyPin(pin string, schemeid irma.SchemeManagerIdentifier) (bool, int, int, error) {
	scheme := client.Configuration.SchemeManagers[schemeid]
	if scheme == nil || !scheme.Distributed() {
		return false, 0, 0, &irma.SessionError{
			Err:       errors.Errorf("Can't verify pin of scheme %s", schemeid.String()),
			ErrorType: irma.ErrorUnknownSchemeManager,
			Info:      schemeid.String(),
		}
	}
	kss := client.keyshareServers[schemeid]
	return verifyPinWorker(pin, kss,
		irma.NewHTTPTransport(scheme.KeyshareServer, !client.Preferences.DeveloperMode),
	)
}

func (client *Client) KeyshareChangePin(manager irma.SchemeManagerIdentifier, oldPin string, newPin string) {
	go func() {
		err := client.keyshareChangePinWorker(manager, oldPin, newPin)
		if err != nil {
			client.handler.ChangePinFailure(manager, err)
		}
	}()
}

func (client *Client) keyshareChangePinWorker(managerID irma.SchemeManagerIdentifier, oldPin string, newPin string) error {
	kss, ok := client.keyshareServers[managerID]
	if !ok {
		return errors.New("Unknown keyshare server")
	}

	transport := irma.NewHTTPTransport(client.Configuration.SchemeManagers[managerID].KeyshareServer, !client.Preferences.DeveloperMode)
	message := keyshareChangepin{
		Username: kss.Username,
		OldPin:   kss.HashedPin(oldPin),
		NewPin:   kss.HashedPin(newPin),
	}

	res := &keysharePinStatus{}
	err := transport.Post("users/change/pin", res, message)
	if err != nil {
		return err
	}

	switch res.Status {
	case kssPinSuccess:
		client.handler.ChangePinSuccess(managerID)
	case kssPinFailure:
		attempts, err := strconv.Atoi(res.Message)
		if err != nil {
			return err
		}
		client.handler.ChangePinIncorrect(managerID, attempts)
	case kssPinError:
		timeout, err := strconv.Atoi(res.Message)
		if err != nil {
			return err
		}
		client.handler.ChangePinBlocked(managerID, timeout)
	default:
		return errors.New("Unknown keyshare response")
	}

	return nil
}

// KeyshareRemove unenrolls the keyshare server of the specified scheme manager.
func (client *Client) KeyshareRemove(manager irma.SchemeManagerIdentifier) error {
	if _, contains := client.keyshareServers[manager]; !contains {
		return errors.New("Can't uninstall unknown keyshare server")
	}
	delete(client.keyshareServers, manager)
	return client.storage.StoreKeyshareServers(client.keyshareServers)
}

// KeyshareRemoveAll removes all keyshare server registrations.
func (client *Client) KeyshareRemoveAll() error {
	client.keyshareServers = map[irma.SchemeManagerIdentifier]*keyshareServer{}
	return client.storage.StoreKeyshareServers(client.keyshareServers)
}

// Add, load and store log entries

// LoadNewestLogs returns the log entries of latest past events
// (sorted from new to old, the result length is limited to max).
func (client *Client) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return client.storage.LoadNewestLogs(max)
}

// LoadLogsBefore returns the log entries of past events that took place before log entry with ID 'beforeIndex'
// (sorted from new to old, the result length is limited to max).
func (client *Client) LoadLogsBefore(beforeIndex uint64, max int) ([]*LogEntry, error) {
	return client.storage.LoadLogsBefore(beforeIndex, max)
}

func (client *Client) SetPreferences(pref Preferences) {
	if pref.DeveloperMode {
		irma.Logger.Info("developer mode enabled")
	} else {
		irma.Logger.Info("developer mode disabled")
	}
	client.Preferences = pref
	_ = client.storage.StorePreferences(client.Preferences)
	client.applyPreferences()
}

func (client *Client) applyPreferences() {}

// ConfigurationUpdated should be run after Configuration.Download().
// For any credential type in the updated scheme to which new attributes were added, this function
// sets the value of these new attributes to 0 in all instances that the client currently has of this
// credential type.
func (client *Client) ConfigurationUpdated(downloaded *irma.IrmaIdentifierSet) error {
	if downloaded == nil || len(downloaded.CredentialTypes) == 0 {
		return nil
	}

	var contains bool
	for id := range downloaded.CredentialTypes {
		if _, contains = client.attributes[id]; !contains {
			continue
		}
		for i := range client.attributes[id] {
			attrs := client.attributes[id][i].Ints
			diff := len(client.Configuration.CredentialTypes[id].AttributeTypes) - (len(attrs) - 1)
			if diff <= 0 {
				continue
			}
			attrs = append(attrs, make([]*big.Int, diff, diff)...)
			for j := len(attrs) - diff; j < len(attrs); j++ {
				attrs[j] = big.NewInt(0)
			}
			client.attributes[id][i].Ints = attrs
			if err := client.storage.StoreAttributes(id, client.attributes[id]); err != nil {
				return err
			}

			if _, contains = client.credentialsCache[id]; !contains {
				continue
			}
			if _, contains = client.credentialsCache[id][i]; !contains {
				continue
			}
			client.credentialsCache[id][i].Attributes = append(
				client.credentialsCache[id][i].Attributes[:1],
				attrs...,
			)
		}
	}

	return nil
}

func (cc *credCandidate) Present() bool {
	return cc.Hash != ""
}

func (dc *DisclosureCandidate) Present() bool {
	return dc.CredentialHash != ""
}

func (dcs DisclosureCandidates) Choose() ([]*irma.AttributeIdentifier, error) {
	var ids []*irma.AttributeIdentifier
	for _, attr := range dcs {
		if !attr.Present() {
			return nil, errors.New("credential not present")
		}
		if attr.Expired {
			return nil, errors.New("cannot choose expired credential")
		}
		if attr.Revoked {
			return nil, errors.New("cannot choose revoked credential")
		}
		if attr.NotRevokable {
			return nil, errors.New("credential does not support revocation")
		}
		ids = append(ids, attr.AttributeIdentifier)
	}
	return ids, nil
}
