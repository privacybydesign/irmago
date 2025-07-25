package irmaclient

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-co-op/gocron"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/internal/concmap"
)

// This file contains most methods of the IrmaClient (c.f. session.go
// and updates.go).
//
// Clients are the main entry point into this package for the user of this package.
// The IrmaClient struct:
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

type IrmaClient struct {
	// Stuff we manage on disk
	secretkey        *secretKey
	attributes       map[irma.CredentialTypeIdentifier][]*irma.AttributeList
	credentialsCache concmap.ConcMap[credLookup, *credential]
	keyshareServers  map[irma.SchemeManagerIdentifier]*keyshareServer
	updates          []update

	lookup map[string]*credLookup

	// Where we store/load IRMA related data to/from
	storage *storage

	// Where we store/load SD-JWT-VC related data to/from
	sdJwtVcStorage           SdJwtVcStorage
	sdJwtVerificationContext sdjwtvc.VerificationContext
	keyBinder                sdjwtvc.KeyBinder

	// Versions the client supports
	minVersion *irma.ProtocolVersion
	maxVersion *irma.ProtocolVersion

	// Other state
	Preferences   Preferences
	Configuration *irma.Configuration
	handler       ClientHandler
	signer        Signer
	sessions      sessions

	jobs       chan func()   // queue of jobs to run
	jobsPause  chan struct{} // sending pauses background jobs
	jobsPaused bool

	credMutex sync.Mutex
}

// NewIrmaClient creates a new IrmaClient that uses the storage
// for (de)serializing itself. conf is the irma_configuration;
// and handler is used for informing the user of new stuff, and when a
// enrollment to a keyshare server needs to happen.
// The client returned by this function has been fully deserialized
// and is ready for use.
//
// NOTE: It is the responsibility of the caller that there exists a (properly
// protected) directory at the path defined in the storage variable!
func NewIrmaClient(
	conf *irma.Configuration,
	handler ClientHandler,
	signer Signer,
	storage *storage,
	sdJwtVerificationContext sdjwtvc.VerificationContext,
	sdJwtVcStorage SdJwtVcStorage,
	keyBinder sdjwtvc.KeyBinder,
) (*IrmaClient, error) {
	var err error

	client := &IrmaClient{
		Configuration:   conf,
		storage:         storage,
		sdJwtVcStorage:  sdJwtVcStorage,
		keyshareServers: make(map[irma.SchemeManagerIdentifier]*keyshareServer),
		attributes:      make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList),
		handler:         handler,
		signer:          signer,
		minVersion:      &irma.ProtocolVersion{Major: 2, Minor: supportedVersions[2][0]},
		maxVersion:      &irma.ProtocolVersion{Major: 2, Minor: supportedVersions[2][len(supportedVersions[2])-1]},
		keyBinder:       keyBinder,
	}

	schemeMgrErr := client.Configuration.ParseOrRestoreFolder()
	// If schemMgrErr is of type SchemeManagerError, we continue and
	// return it at the end; otherwise bail out now
	_, isSchemeMgrErr := schemeMgrErr.(*irma.SchemeManagerError)
	if schemeMgrErr != nil && !isSchemeMgrErr {
		return nil, fmt.Errorf("scheme manager error: %v", schemeMgrErr)
	}

	// Perform new update functions from clientUpdates, if any
	if err = client.update(); err != nil {
		return nil, fmt.Errorf("client update failed: %v", err)
	}

	// Load our stuff
	if client.Preferences, err = client.storage.LoadPreferences(); err != nil {
		return nil, fmt.Errorf("failed to load preferences: %v", err)
	}
	client.applyPreferences()

	err = client.loadCredentialStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to load credential storage: %v", err)
	}

	client.sessions = sessions{client: client, sessions: map[string]*session{}}

	gocron.SetPanicHandler(func(jobName string, recoverData interface{}) {
		var details string
		b, err := json.Marshal(recoverData)
		if err == nil {
			details = string(b)
		} else {
			details = "failed to marshal recovered data: " + err.Error()
		}
		client.reportError(errors.Errorf("panic during gocron job '%s': %s", jobName, details))
	})

	client.jobs = make(chan func(), 100)
	client.initRevocation()
	client.StartJobs()

	client.sdJwtVerificationContext = sdJwtVerificationContext

	return client, schemeMgrErr
}

func (client *IrmaClient) Close() error {
	client.PauseJobs()
	client.Configuration.Scheduler.Stop()
	return client.storage.Close()
}

func (client *IrmaClient) loadCredentialStorage() (err error) {
	if client.secretkey, err = client.storage.LoadSecretKey(); err != nil {
		return
	}
	if client.attributes, err = client.storage.LoadAttributes(); err != nil {
		return
	}
	if client.keyshareServers, err = client.storage.LoadKeyshareServers(); err != nil {
		return
	}

	client.lookup = map[string]*credLookup{}
	for _, attrlistlist := range client.attributes {
		for i, attrlist := range attrlistlist {
			client.lookup[attrlist.Hash()] = &credLookup{id: attrlist.CredentialType().Identifier(), counter: i}
		}
	}
	client.credentialsCache = concmap.New[credLookup, *credential]()
	return
}

func (client *IrmaClient) reportError(err error) {
	irma.Logger.Error(err)
	client.handler.ReportError(err)
}

// StartJobs performs scheduled background jobs in separate goroutines.
// Pause pending jobs with PauseJobs().
func (client *IrmaClient) StartJobs() {
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
func (client *IrmaClient) PauseJobs() {
	irma.Logger.Debug("pausing jobs")
	if client.jobsPaused {
		irma.Logger.Debug("already paused")
		return
	}
	client.jobsPaused = true
	close(client.jobsPause)
}

// CredentialInfoList returns a list of information of all contained credentials.
func (client *IrmaClient) CredentialInfoList() irma.CredentialInfoList {
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
// immediately, and optionally cm.attributes as well.
func (client *IrmaClient) addCredential(cred *credential) (err error) {
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
		if err = client.remove(id, index); err != nil {
			return err
		}
	}

	// If this is a singleton credential type, ensure we have at most one by removing any previous instance
	// If a credential already exists with exactly the same attribute values (except metadata), delete the previous credential
	if !id.Empty() {
		if cred.CredentialType().IsSingleton {
			for len(client.attrs(id)) != 0 {
				if err = client.remove(id, 0); err != nil {
					return
				}
			}
		}

		for i := len(client.attrs(id)) - 1; i >= 0; i-- { // Go backwards through array because remove manipulates it
			if client.attrs(id)[i].EqualsExceptMetadata(cred.attrs) {
				if err = client.remove(id, i); err != nil {
					return
				}
			}
		}
	}

	// Append the new cred to our attributes and credentials
	client.attributes[id] = append(client.attrs(id), cred.attrs)
	if !id.Empty() {
		counter := len(client.attributes[id]) - 1
		credlookup := credLookup{id: id, counter: counter}
		client.credentialsCache.Set(credlookup, cred)
		client.lookup[cred.attrs.Hash()] = &credlookup
	}

	return client.storage.Transaction(func(tx *transaction) error {
		if err = client.storage.TxStoreSignature(tx, cred); err != nil {
			return err
		}
		return client.storage.TxStoreAttributes(tx, id, client.attributes[id])
	})
}

func generateSecretKey() (*secretKey, error) {
	key, err := gabi.GenerateSecretAttribute()
	if err != nil {
		return nil, err
	}
	return &secretKey{Key: key}, nil
}

// Removal methods

func (client *IrmaClient) remove(id irma.CredentialTypeIdentifier, index int) error {
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
		if err := client.storage.TxDeleteSignature(tx, attrs.Hash()); err != nil {
			return err
		}
		if err := client.storage.TxStoreAttributes(tx, id, client.attributes[id]); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Remove credential from cache
	client.credentialsCache.Delete(credLookup{id: id, counter: index})
	delete(client.lookup, attrs.Hash())
	for i, attrs := range client.attributes[id] {
		client.lookup[attrs.Hash()].counter = i
	}
	return nil
}

// RemoveCredential removes the specified credential if that is allowed.
func (client *IrmaClient) RemoveCredential(id irma.CredentialTypeIdentifier, index int) error {
	if client.Configuration.CredentialTypes[id].DisallowDelete {
		return errors.Errorf("configuration does not allow removal of credential type %s", id.String())
	}
	return client.remove(id, index)
}

// RemoveCredentialByHash removes the specified credential.
func (client *IrmaClient) RemoveCredentialByHash(hash string) error {
	cred, index, err := client.credentialByHash(hash)
	if err != nil {
		return err
	}
	return client.RemoveCredential(cred.CredentialType().Identifier(), index)
}

// RemoveStorage removes all attributes, signatures, logs and userdata.
// This includes the user's secret key, keyshare servers and preferences/updates.
// A fresh secret key is installed.
func (client *IrmaClient) RemoveStorage() error {
	var err error

	// Remove data from memory
	client.attributes = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	client.keyshareServers = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	client.credentialsCache = concmap.New[credLookup, *credential]()
	client.lookup = make(map[string]*credLookup)

	if err = client.storage.DeleteAll(); err != nil {
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

// attrs returns cm.attributes[id], initializing it to an empty slice if necessary
func (client *IrmaClient) attrs(id irma.CredentialTypeIdentifier) []*irma.AttributeList {
	list, exists := client.attributes[id]
	if !exists {
		list = make([]*irma.AttributeList, 0, 1)
		client.attributes[id] = list
	}
	return list
}

// Attributes returns the attribute list of the requested credential, or nil if we do not have it.
func (client *IrmaClient) Attributes(id irma.CredentialTypeIdentifier, counter int) (attributes *irma.AttributeList) {
	list := client.attrs(id)
	if len(list) <= counter {
		return
	}
	return list[counter]
}

func (client *IrmaClient) attributesByHash(hash string) (*irma.AttributeList, int) {
	lookup, present := client.lookup[hash]
	if !present {
		return nil, 0
	}
	return client.attributes[lookup.id][lookup.counter], lookup.counter
}

func (client *IrmaClient) credentialByHash(hash string) (*credential, int, error) {
	attrs, index := client.attributesByHash(hash)
	if attrs != nil {
		cred, err := client.credential(attrs.CredentialType().Identifier(), index)
		return cred, index, err
	}
	return nil, 0, nil
}

func (client *IrmaClient) credentialByID(id irma.CredentialIdentifier) (*credential, error) {
	cred, _, err := client.credentialByHash(id.Hash)
	return cred, err
}

// credential returns the requested credential, or nil if we do not have it.
// FIXME: this function can cause concurrent map writes panics when invoked concurrently simultaneously,
// in client.Configuration.publicKeys and client.credentialsCache.
func (client *IrmaClient) credential(id irma.CredentialTypeIdentifier, counter int) (cred *credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during New(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	cred = client.credentialsCache.Get(credLookup{id, counter})
	if cred != nil {
		return
	}

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
	cred, err = newCredential(&gabi.Credential{
		Attributes:           append([]*big.Int{client.secretkey.Key}, attrs.Ints...),
		Signature:            sig,
		NonRevocationWitness: witness,
		Pk:                   pk,
	}, attrs, client.Configuration)
	if err != nil {
		return nil, err
	}
	client.credentialsCache.Set(credLookup{id, counter}, cred)
	return cred, nil
}

// Methods used in the IRMA protocol

// credCandidates returns a list containing a list of candidate credential instances for each item
// in the conjunction. (A credential instance from the client is a candidate it it contains
// attributes required in this conjunction). If one credential type occurs multiple times in the
// conjunction it is not added twice.
func (client *IrmaClient) credCandidates(request irma.SessionRequest, con irma.AttributeCon) (credCandidateSet, bool, error) {
	var candidates [][]*credCandidate
	satisfiable := true

	for _, credTypeID := range con.CredentialTypes() {
		attrlistlist := client.attributes[credTypeID]
		var c []*credCandidate
		haveUsableCred := false
		for _, attrlist := range attrlistlist {
			satisfies, usable := client.satisfiesCon(request, attrlist, con)
			if satisfies { // add it to the list, even if they are unusable
				c = append(c, &credCandidate{Type: credTypeID, Hash: attrlist.Hash()})
				if usable { // having one usable credential will do
					haveUsableCred = true
				}
			}
		}
		if !haveUsableCred {
			// if for one of the credential types in this conjunction we don't have candidates,
			// then the entire conjunction is unsatisfiable
			satisfiable = false
		}
		// Determine whether the session request forces an attribute value for any attribute requested from this credential.
		fixedAttrValue := false
		for _, attr := range con {
			if attr.Type.CredentialTypeIdentifier() != credTypeID {
				continue
			}
			if attr.Value != nil {
				fixedAttrValue = true
			}
		}
		if len(c) == 0 {
			satisfiable = false
		}
		if client.addCredSuggestion(request, credTypeID, fixedAttrValue, len(c) != 0) {
			// When there are no candidates or when the credential is non-singleton, excluding some nonsensical cases,
			// add an "empty" credential (i.e. without hash) as a suggestion to the user
			c = append(c, &credCandidate{Type: credTypeID})
		}
		candidates = append(candidates, c)
	}
	return candidates, satisfiable, nil
}

// addCredSuggestion decides whether or not to include an "empty" credential candidate
// (i.e. without hash) with the disclosure candidates to the user as a suggestion.
func (client *IrmaClient) addCredSuggestion(
	request irma.SessionRequest, credTypeID irma.CredentialTypeIdentifier,
	fixedAttrValue, haveCandidates bool,
) bool {
	credType := client.Configuration.CredentialTypes[credTypeID]
	credDeprecatedSince := credType.DeprecatedSince
	issuerDeprecatedSince := client.Configuration.Issuers[credType.IssuerIdentifier()].DeprecatedSince
	now := irma.Timestamp(time.Now())

	if (!credDeprecatedSince.IsZero() && credDeprecatedSince.Before(now)) ||
		(!issuerDeprecatedSince.IsZero() && issuerDeprecatedSince.Before(now)) {
		return false
	}

	// Show option to add extra cards of non-singleton
	if (credType.IssueURL != nil && len(*credType.IssueURL) != 0) && !credType.IsSingleton && !fixedAttrValue {
		return true
	}

	if haveCandidates {
		return false
	}

	if isreq, ok := request.(*irma.IssuanceRequest); ok {
		for _, req := range isreq.Credentials {
			if req.CredentialTypeID == credTypeID {
				return false
			}
		}
	}

	return true
}

// satsifiesCon returns:
//   - if the attrs can satisfy the conjunction (as long as it is usable),
//   - if the attrs are usable (they are not expired, or revoked, or not revocation-aware while
//     a nonrevocation proof is required).
func (client *IrmaClient) satisfiesCon(request irma.SessionRequest, attrs *irma.AttributeList, con irma.AttributeCon) (bool, bool) {
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
	usable := !attrs.Revoked && (!request.Base().RequestsRevocation(credtype) || cred.NonRevocationWitness != nil)

	skipExpiryCheck := slices.Contains(request.Disclosure().SkipExpiryCheck, attrs.CredentialType().Identifier())
	if !skipExpiryCheck {
		usable = usable && attrs.IsValid()
	}

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

func (set credCandidateSet) expand(client *IrmaClient, base *irma.BaseRequest, con irma.AttributeCon) ([]DisclosureCandidates, error) {
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
					Value: irma.NewTranslatedString(attr.Value),
				}
				if credopt.Present() {
					attrlist, _ := client.attributesByHash(credopt.Hash)
					cred, _, err := client.credentialByHash(credopt.Hash)
					if err != nil {
						return nil, err
					}
					attropt.Expired = !attrlist.IsValid()
					attropt.Revoked = attrlist.Revoked
					attropt.NotRevokable = cred.NonRevocationWitness == nil && base.RequestsRevocation(credopt.Type)
				}
				candidateSet = append(candidateSet, attropt)
			}
		}
		result = append(result, candidateSet)
	}

	return result, nil
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
func (client *IrmaClient) candidatesDisCon(request irma.SessionRequest, discon irma.AttributeDisCon) (
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
		c, conSatisfiable, err := client.credCandidates(request, con)
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
		expanded, err := c.expand(client, request.Base(), con)
		if err != nil {
			return nil, false, err
		}
		candidates = append(candidates, expanded...)
	}

	return
}

// Candidates returns a list of options for the user to choose from,
// given a session request and the credentials currently in storage.
func (client *IrmaClient) Candidates(request irma.SessionRequest) (
	candidates [][]DisclosureCandidates, satisfiable bool, err error,
) {
	condiscon := request.Disclosure().Disclose
	candidates = make([][]DisclosureCandidates, len(condiscon))

	satisfiable = true
	client.credMutex.Lock()
	defer client.credMutex.Unlock()
	for i, discon := range condiscon {
		cands, disconSatisfiable, err := client.candidatesDisCon(request, discon)
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
func (client *IrmaClient) groupCredentials(choice *irma.DisclosureChoice) (
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
func (client *IrmaClient) ProofBuilders(choice *irma.DisclosureChoice, request irma.SessionRequest,
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
		builder, err = cred.CreateDisclosureProofBuilder(grp.attrs, nil, nonrev)
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
func (client *IrmaClient) Proofs(choice *irma.DisclosureChoice, request irma.SessionRequest) (*irma.Disclosure, *atum.Timestamp, error) {
	builders, choices, timestamp, err := client.ProofBuilders(choice, request)
	if err != nil {
		return nil, nil, err
	}

	_, issig := request.(*irma.SignatureRequest)
	proofs, err := builders.BuildProofList(request.Base().GetContext(), request.GetNonce(timestamp), issig)
	if err != nil {
		return nil, nil, err
	}
	return &irma.Disclosure{
		Proofs:  proofs,
		Indices: choices,
	}, timestamp, nil
}

// generateIssuerProofNonce generates a nonce which the issuer must use in its gabi.ProofS.
func generateIssuerProofNonce() (*big.Int, error) {
	return gabi.GenerateNonce()
}

// IssuanceProofBuilders constructs a list of proof builders in the issuance protocol
// for the future credentials as well as possibly any disclosed attributes, and generates
// a nonce against which the issuer's proof of knowledge must verify.
func (client *IrmaClient) IssuanceProofBuilders(
	request *irma.IssuanceRequest, choice *irma.DisclosureChoice, keyshareSession *keyshareSession,
) (gabi.ProofBuilderList, irma.DisclosedAttributeIndices, *big.Int, error) {
	issuerProofNonce, err := generateIssuerProofNonce()
	if err != nil {
		return nil, nil, nil, err
	}
	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{})

	var keysharePs = map[irma.SchemeManagerIdentifier]*irma.PMap{}
	if keyshareSession != nil {
		keysharePs, err = keyshareSession.getKeysharePs(request)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	for _, futurecred := range request.Credentials {
		var pk *gabikeys.PublicKey
		keyID := futurecred.PublicKeyIdentifier()
		schemeID := keyID.Issuer.SchemeManagerIdentifier()
		distributed := client.Configuration.SchemeManagers[schemeID].Distributed()
		var keyshareP *big.Int
		var present bool
		if distributed {
			keyshareP, present = keysharePs[schemeID].Ps[keyID]
			if distributed && !present {
				return nil, nil, nil, errors.Errorf("missing keyshareP for %s-%d", keyID.Issuer, keyID.Counter)
			}
		}

		pk, err = client.Configuration.PublicKey(futurecred.CredentialTypeID.IssuerIdentifier(), futurecred.KeyCounter)
		if err != nil {
			return nil, nil, nil, err
		}
		credtype := client.Configuration.CredentialTypes[futurecred.CredentialTypeID]
		credBuilder, err := gabi.NewCredentialBuilder(pk, request.GetContext(),
			client.secretkey.Key, issuerProofNonce, keyshareP, credtype.RandomBlindAttributeIndices())
		if err != nil {
			return nil, nil, nil, err
		}
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
func (client *IrmaClient) IssueCommitments(
	request *irma.IssuanceRequest,
	choice *irma.DisclosureChoice,
) (*irma.IssueCommitmentMessage, gabi.ProofBuilderList, error) {
	builders, choices, issuerProofNonce, err := client.IssuanceProofBuilders(request, choice, nil)
	if err != nil {
		return nil, nil, err
	}
	proofs, err := builders.BuildProofList(request.GetContext(), request.GetNonce(nil), false)
	if err != nil {
		return nil, nil, err
	}

	keyBindingPubKeys, err := client.keyBinder.CreateKeyPairs(irma.CalculateAmountOfSdJwtsToIssue(request))
	if err != nil {
		return nil, nil, err
	}

	return &irma.IssueCommitmentMessage{
		IssueCommitmentMessage: &gabi.IssueCommitmentMessage{
			Proofs: proofs,
			Nonce2: issuerProofNonce,
		},
		Indices:           choices,
		KeyBindingPubKeys: keyBindingPubKeys,
	}, builders, nil
}

// ConstructCredentials constructs and saves new credentials using the specified issuance signature messages
// and credential builders.
func (client *IrmaClient) ConstructCredentials(msg []*gabi.IssueSignatureMessage, request *irma.IssuanceRequest, builders gabi.ProofBuilderList) error {
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
		req := request.Credentials[i-offset]
		if !req.RevocationSupported && (nonrevAttr != nil) {
			return errors.New("credential signature unexpectedly containend nonrevocation witness")
		}
		if req.RevocationSupported && (nonrevAttr == nil) {
			return errors.New("credential signature did not contain nonrevocation witness")
		}
		attrs, err := req.AttributeList(
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

func (client *IrmaClient) genSchemeManagersList(enrolled bool) []irma.SchemeManagerIdentifier {
	list := []irma.SchemeManagerIdentifier{}
	for name, manager := range client.Configuration.SchemeManagers {
		if _, contains := client.keyshareServers[name]; manager.Distributed() && contains == enrolled {
			list = append(list, manager.Identifier())
		}
	}
	return list
}

func (client *IrmaClient) UnenrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.genSchemeManagersList(false)
}

func (client *IrmaClient) EnrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.genSchemeManagersList(true)
}

// KeyshareEnroll attempts to enroll at the keyshare server of the specified scheme manager.
func (client *IrmaClient) KeyshareEnroll(manager irma.SchemeManagerIdentifier, email *string, pin string, lang string) {
	go func() {
		err := client.keyshareEnrollWorker(manager, email, pin, lang)
		if err != nil {
			client.handler.EnrollmentFailure(manager, err)
		}
	}()
}

func (client *IrmaClient) keyshareEnrollWorker(managerID irma.SchemeManagerIdentifier, email *string, pin string, lang string) error {
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

	// We expect that the PIN is equal across all keyshare servers. Therefore, we verify the PIN at one other
	// keyshare server. We don't check all servers to prevent issues when custom keyshare servers are not available.
	var err error
	pinCorrect := true
	for kssManagerID, kss := range client.keyshareServers {
		if kss.PinOutOfSync {
			continue
		}
		pinCorrect, _, _, err = client.KeyshareVerifyPin(pin, kssManagerID)
		if err == nil {
			break
		}
	}
	if err != nil {
		return irma.WrapErrorPrefix(err, "failed to validate pin")
	}
	if !pinCorrect {
		return errors.New("incorrect pin")
	}

	keyname := challengeResponseKeyName(managerID)
	pk, err := client.signer.PublicKey(keyname)
	if err != nil {
		return err
	}

	kss, err := newKeyshareServer(managerID)
	if err != nil {
		return err
	}

	jwtt, err := SignerCreateJWT(client.signer, keyname, irma.KeyshareEnrollmentClaims{
		KeyshareEnrollmentData: irma.KeyshareEnrollmentData{
			Email:     email,
			Pin:       kss.HashedPin(pin),
			Language:  lang,
			PublicKey: pk,
		},
	})
	if err != nil {
		return err
	}

	transport := irma.NewHTTPTransport(manager.KeyshareServer, !client.Preferences.DeveloperMode)
	qr := &irma.Qr{}
	err = transport.Post("client/register", qr, irma.KeyshareEnrollment{EnrollmentJWT: jwtt})
	if err != nil {
		return err
	}

	// We add the new keyshare server to the client here, without saving it to disk,
	// and start the issuance session for the keyshare server login attribute -
	// keyshare.go needs the relevant keyshare server to be present in the client.
	// If the session succeeds or fails, the keyshare server is stored to disk or
	// removed from the client by the keyshareEnrollmentHandler.
	client.keyshareServers[managerID] = kss
	handler := &backgroundIssuanceHandler{
		pin: pin,
		credentialsToBeIssuedCallback: func(creds []*irma.CredentialRequest) {
			// We need to store the keyshare username before the issuance permission is granted.
			// Otherwise, authentication to the keyshare server fails during issuance of the keyshare attribute.
			for _, attr := range creds[0].Attributes {
				kss.Username = attr
				break
			}
		},
		resultErr: make(chan error),
	}
	client.newQrSession(qr, handler)
	go func() {
		err := <-handler.resultErr
		if err != nil {
			client.handler.EnrollmentFailure(managerID, irma.WrapErrorPrefix(err, "keyshare attribute issuance"))
			return
		}
		err = client.storage.StoreKeyshareServers(client.keyshareServers)
		if err != nil {
			client.handler.EnrollmentFailure(managerID, err)
			return
		}
		client.handler.EnrollmentSuccess(kss.SchemeManagerIdentifier)
	}()

	return nil
}

func challengeResponseKeyName(scheme irma.SchemeManagerIdentifier) string {
	// Use a dot as separator because those never occur in scheme names
	return scheme.Name() + ".challengeResponseKey"
}

// KeyshareVerifyPin verifies the specified PIN at the keyshare server, returning if it succeeded;
// if not, how many tries are left, or for how long the user is blocked. If an error is returned
// it is of type *irma.SessionError.
func (client *IrmaClient) KeyshareVerifyPin(
	pin string,
	schemeid irma.SchemeManagerIdentifier,
) (success bool, triesRemaing int, blockedSecs int, err error) {
	scheme := client.Configuration.SchemeManagers[schemeid]
	if scheme == nil || !scheme.Distributed() {
		return false, 0, 0, &irma.SessionError{
			Err:       errors.Errorf("Can't verify pin of scheme %s", schemeid.String()),
			ErrorType: irma.ErrorUnknownSchemeManager,
			Info:      schemeid.String(),
		}
	}
	kss := client.keyshareServers[schemeid]
	transport := irma.NewHTTPTransport(scheme.KeyshareServer, !client.Preferences.DeveloperMode)
	success, tries, blocked, err := client.verifyPinWorker(pin, kss, transport)
	if err == nil && success {
		client.ensureKeyshareAttributeValid(pin, kss, transport)
	}
	return success, tries, blocked, err
}

func (client *IrmaClient) KeyshareChangePin(oldPin string, newPin string) {
	go func() {
		// Check whether all keyshare servers are available.
		for schemeID, kss := range client.keyshareServers {
			if kss.PinOutOfSync {
				continue
			}
			success, attempts, blocked, err := client.KeyshareVerifyPin(oldPin, schemeID)
			if err != nil {
				client.handler.ChangePinFailure(schemeID, err)
				return
			}
			if !success {
				if attempts > 0 {
					client.handler.ChangePinIncorrect(schemeID, attempts)
				} else {
					client.handler.ChangePinBlocked(schemeID, blocked)
				}
				return
			}
		}

		// Change the PIN across all keyshare servers.
		var updatedSchemes []irma.SchemeManagerIdentifier
		var err error
		for schemeID, kss := range client.keyshareServers {
			if kss.PinOutOfSync {
				continue
			}

			err = client.keyshareChangePinWorker(schemeID, oldPin, newPin)
			if err != nil {
				client.handler.ChangePinFailure(schemeID, err)
				break
			}

			updatedSchemes = append(updatedSchemes, schemeID)
		}

		// If an error occurred, try to undo all changes we already made. In case this fails,
		// we set the PinOutOfSync flag for that particular enrollment.
		if err != nil {
			pinOutOfSync := false
			for _, updatedManager := range updatedSchemes {
				err = client.keyshareChangePinWorker(updatedManager, newPin, oldPin)
				if err != nil {
					client.reportError(err)
					client.keyshareServers[updatedManager].PinOutOfSync = true
					pinOutOfSync = true
				}
			}
			if pinOutOfSync {
				err = client.storage.StoreKeyshareServers(client.keyshareServers)
				if err != nil {
					client.reportError(err)
				}
			}
			return
		}

		client.handler.ChangePinSuccess()
	}()
}

func (client *IrmaClient) keyshareChangePinWorker(managerID irma.SchemeManagerIdentifier, oldPin string, newPin string) error {
	kss, ok := client.keyshareServers[managerID]
	if !ok {
		return errors.New("Unknown keyshare server")
	}

	transport := irma.NewHTTPTransport(client.Configuration.SchemeManagers[managerID].KeyshareServer, !client.Preferences.DeveloperMode)

	claims := irma.KeyshareChangePinClaims{
		KeyshareChangePinData: irma.KeyshareChangePinData{
			Username: kss.Username,
			OldPin:   kss.HashedPin(oldPin),
			NewPin:   kss.HashedPin(newPin),
		},
	}
	jwtt, err := SignerCreateJWT(client.signer, challengeResponseKeyName(managerID), claims)
	if err != nil {
		return err
	}

	res := &irma.KeysharePinStatus{}
	err = transport.Post("users/change/pin", res, irma.KeyshareChangePin{
		ChangePinJWT: jwtt,
	})
	if err != nil {
		return err
	}

	switch res.Status {
	case kssPinSuccess:
		// The cached authorization token is invalid now, so we have to refresh this.
		ok, _, _, err = client.KeyshareVerifyPin(newPin, managerID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.Errorf("keyshare authorization token could not be refreshed for scheme %s", managerID)
		}
		return nil
	case kssPinFailure:
		return errors.Errorf("incorrect PIN for scheme %s", managerID)
	case kssPinError:
		return errors.Errorf("user account is blocked for scheme %s", managerID)
	default:
		return errors.Errorf("unknown keyshare response for scheme %s", managerID)
	}
}

// KeyshareRemove unenrolls the keyshare server of the specified scheme manager and removes all associated credentials.
func (client *IrmaClient) KeyshareRemove(manager irma.SchemeManagerIdentifier) error {
	if _, contains := client.keyshareServers[manager]; !contains {
		return errors.New("can't uninstall unknown keyshare server")
	}
	return client.stripStorage([]irma.SchemeManagerIdentifier{manager}, false)
}

// KeyshareRemoveAll removes all keyshare server registrations and associated credentials.
func (client *IrmaClient) KeyshareRemoveAll() error {
	var managers []irma.SchemeManagerIdentifier
	for schemeID := range client.keyshareServers {
		managers = append(managers, schemeID)
	}
	return client.stripStorage(managers, false)
}

// stripStorage removes all credentials and optionally removes all logs of the specified schemes from storage.
func (client *IrmaClient) stripStorage(schemeIDs []irma.SchemeManagerIdentifier, removeLogs bool) error {
	client.credMutex.Lock()
	defer client.credMutex.Unlock()

	defer func() {
		err := client.loadCredentialStorage()
		if err != nil {
			// Cached storage is out-of-sync with real storage, so we can't do anything but report the error and
			// close the client to prevent unexpected changes.
			client.reportError(err)
			_ = client.Close()
		}
	}()

	remainingSchemes := make(map[irma.SchemeManagerIdentifier]struct{})
	for schemeID := range client.Configuration.SchemeManagers {
		remainingSchemes[schemeID] = struct{}{}
	}
	for _, schemeID := range schemeIDs {
		delete(client.keyshareServers, schemeID)
		delete(remainingSchemes, schemeID)
	}

	return client.storage.Transaction(func(tx *transaction) error {
		// Delete all credentials of given schemes.
		for _, cred := range client.CredentialInfoList() {
			if _, ok := remainingSchemes[irma.NewSchemeManagerIdentifier(cred.SchemeManagerID)]; !ok {
				err := client.storage.TxStoreAttributes(tx, cred.Identifier(), []*irma.AttributeList{})
				if err != nil {
					return err
				}
				err = client.storage.TxDeleteSignature(tx, cred.Hash)
				if err != nil {
					return err
				}
			}
		}

		// Remove all logs of given schemes, if necessary.
		if removeLogs {
			err := client.storage.TxIterateLogs(tx, func(log *LogEntry) error {
				shouldDelete := false
				for credID := range log.Removed {
					if _, ok := remainingSchemes[credID.SchemeManagerIdentifier()]; !ok {
						shouldDelete = true
					}
				}

				request, err := log.SessionRequest()
				if err != nil {
					return err
				}
				if request != nil {
					for schemeID := range request.Identifiers().SchemeManagers {
						if _, ok := remainingSchemes[schemeID]; !ok {
							shouldDelete = true
						}
					}
				}

				if shouldDelete {
					return client.storage.TxDeleteLogEntry(tx, log.ID)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}

		return client.storage.TxStoreKeyshareServers(tx, client.keyshareServers)
	})
}

func (client *IrmaClient) ensureKeyshareAttributeValid(pin string, kss *keyshareServer, transport *irma.HTTPTransport) {
	// The user has no way to deal with the errors that may occur here, so we just report them and return.
	manager := client.Configuration.SchemeManagers[kss.SchemeManagerIdentifier]
	attrs := client.Attributes(irma.NewAttributeTypeIdentifier(manager.KeyshareAttribute).CredentialTypeIdentifier(), 0)
	if attrs == nil {
		client.reportError(errors.New("keyshare attribute not present"))
		return
	}
	// Renew the keyshare attribute if it expires within a month.
	if attrs.MetadataAttribute.Expiry().Before(time.Now().AddDate(0, 1, 0)) {
		qr := &irma.Qr{}
		if err := transport.Get("users/renewKeyshareAttribute", &qr); err != nil {
			client.reportError(err)
			return
		}
		handler := &backgroundIssuanceHandler{
			pin:       pin,
			resultErr: make(chan error),
		}
		client.newQrSession(qr, handler)
		if err := <-handler.resultErr; err != nil {
			client.reportError(err)
			return
		}
	}
}

// Add, load and store log entries

// LoadNewestLogs returns the log entries of latest past events
// (sorted from new to old, the result length is limited to max).
func (client *IrmaClient) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return client.storage.LoadNewestLogs(max)
}

// LoadLogsBefore returns the log entries of past events that took place before log entry with ID 'beforeIndex'
// (sorted from new to old, the result length is limited to max).
func (client *IrmaClient) LoadLogsBefore(beforeIndex uint64, max int) ([]*LogEntry, error) {
	return client.storage.LoadLogsBefore(beforeIndex, max)
}

func (client *IrmaClient) SetPreferences(pref Preferences) {
	if pref.DeveloperMode {
		irma.Logger.Info("developer mode enabled")
	} else {
		irma.Logger.Info("developer mode disabled")
	}
	client.Preferences = pref
	_ = client.storage.StorePreferences(client.Preferences)
	client.applyPreferences()
}

func (client *IrmaClient) applyPreferences() {}

// ConfigurationUpdated should be run after Configuration.Download().
// For any credential type in the updated scheme to which new attributes were added, this function
// sets the value of these new attributes to 0 in all instances that the client currently has of this
// credential type.
func (client *IrmaClient) ConfigurationUpdated(downloaded *irma.IrmaIdentifierSet) error {
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
			attrs = append(attrs, make([]*big.Int, diff)...)
			for j := len(attrs) - diff; j < len(attrs); j++ {
				attrs[j] = big.NewInt(0)
			}
			client.attributes[id][i].Ints = attrs
			if err := client.storage.StoreAttributes(id, client.attributes[id]); err != nil {
				return err
			}

			cred := client.credentialsCache.Get(credLookup{id, i})
			if cred == nil {
				return nil
			}
			cred.Attributes = append(cred.Attributes[:1], attrs...)
		}
	}

	return nil
}

// RemoveScheme removes the given scheme manager and all credentials and log entries related to it.
func (client *IrmaClient) RemoveScheme(schemeID irma.SchemeManagerIdentifier) error {
	scheme, ok := client.Configuration.SchemeManagers[schemeID]
	if !ok {
		return errors.New("unknown scheme manager")
	}

	isInAssets, err := client.Configuration.IsInAssets(scheme)
	if err != nil {
		return err
	}
	if isInAssets {
		return errors.New("cannot remove scheme manager that is in assets")
	}

	err = client.stripStorage([]irma.SchemeManagerIdentifier{schemeID}, true)
	if err != nil {
		return err
	}
	err = client.Configuration.DangerousDeleteScheme(scheme)
	if err != nil {
		return err
	}
	return client.Configuration.ParseFolder()
}

// RemoveRequestorScheme removes the given requestor scheme and all requestors and issue wizards related to it.
func (client *IrmaClient) RemoveRequestorScheme(schemeID irma.RequestorSchemeIdentifier) error {
	scheme, ok := client.Configuration.RequestorSchemes[schemeID]
	if !ok {
		return errors.New("unknown requestor scheme")
	}
	err := client.Configuration.DangerousDeleteScheme(scheme)
	if err != nil {
		return err
	}
	return client.Configuration.ParseFolder()
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

func (client *IrmaClient) SetSdJwtVerificationContext(context sdjwtvc.VerificationContext) {
	client.sdJwtVerificationContext = context
}

// VerifyAndStoreSdJwts verifies the SD-JWTs and stores them in the SdJwtVcStorage.
// SD-JWTs that are batch-issued should all have the exact same credential info (issuer, id, signedOn, expires, etc.), otherwise they cannot be stored together correctly.
func (client *IrmaClient) VerifyAndStoreSdJwts(sdjwts []sdjwtvc.SdJwtVc, requestedCredentials []*irma.CredentialRequest) error {
	// TODO: check if the correct amount of credentials has been issued for the requestedCredentials for batch requests
	type credentialTuple struct {
		credInfo *irma.CredentialInfo
		sdjwt    sdjwtvc.SdJwtVc
	}
	credentialsMap := make(map[string][]credentialTuple)

	for _, sdjwt := range sdjwts {
		// TODO: check if the SD-JWT adheres to the requested credentials (e.g. if the credential ID and attributes etc match) ?
		// If we don't check this, issuers might issue SD-JWTs that do not match the corresponding IRMA credential
		credInfo, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwt, client.sdJwtVerificationContext)
		if err != nil {
			return err
		}

		// We use the credential info hash as the key to store the SD-JWTs in a map, NOT the credential info or credential ID.
		// Because it is possible that multiple credentials with same credential ID, but different data (e.g. different attributes or minor differences in signedOn/expires)
		// can be issued in a single request, we need to use the hash of the data itself to distinguish between them.
		key := credInfo.Hash
		tuple := credentialTuple{
			credInfo: credInfo,
			sdjwt:    sdjwt,
		}
		if _, exists := credentialsMap[key]; !exists {
			credentialsMap[key] = []credentialTuple{tuple}
		} else {
			credentialsMap[key] = append(credentialsMap[key], tuple)
		}
	}

	// Now that we've grouped the SD-JWTs by their credential info hash, we can store them
	for _, v := range credentialsMap {
		firstCredInfo := v[0].credInfo
		client.sdJwtVcStorage.StoreCredential(*firstCredInfo, sdjwts)
	}

	return nil
}

type credLookup struct {
	id      irma.CredentialTypeIdentifier
	counter int
}

type credCandidateSet [][]*credCandidate

type credCandidate irma.CredentialIdentifier

type DisclosureCandidate struct {
	*irma.AttributeIdentifier
	Value        irma.TranslatedString
	Expired      bool
	Revoked      bool
	NotRevokable bool
}

type DisclosureCandidates []*DisclosureCandidate

type secretKey struct {
	Key *big.Int
}
