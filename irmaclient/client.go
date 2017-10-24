package irmaclient

import (
	"crypto/rand"
	"math/big"
	"sort"
	"time"

	"github.com/credentials/go-go-gadget-paillier"
	"github.com/credentials/irmago"
	"github.com/credentials/irmago/internal/fs"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// This file contains most methods of the Client (c.f. session.go
// and updates.go).
//
// The storage of credentials is split up in several parts:
//
// - The CL-signature of each credential is stored separately, so that we can
// load it on demand (i.e., during an IRMA session), instead of immediately
// at initialization.
//
// - The attributes of all credentials are stored together, as they all
// immediately need to be available anyway,
//
// - The secret key (the zeroth attribute of every credential), being the same
// across all credentials, is stored only once in a separate file (storing this
// in multiple places would be bad).

// Client (de)serializes credentials and keyshare server information
// from storage; as well as logs of earlier IRMA sessions; it provides access
// to the attributes and all related information of its credentials;
// it is the starting point for new IRMA sessions; and it computes some
// of the messages in the client side of the IRMA protocol.
type Client struct {
	// Stuff we manage on disk
	secretkey        *secretKey
	attributes       map[irmago.CredentialTypeIdentifier][]*irmago.AttributeList
	credentials      map[irmago.CredentialTypeIdentifier]map[int]*credential
	keyshareServers  map[irmago.SchemeManagerIdentifier]*keyshareServer
	paillierKeyCache *paillierPrivateKey
	logs             []*LogEntry
	updates          []update

	// Where we store/load it to/from
	storage storage

	// Other state
	ConfigurationStore       *irmago.ConfigurationStore
	UnenrolledSchemeManagers []irmago.SchemeManagerIdentifier
	irmaConfigurationPath    string
	androidStoragePath       string
	handler                  ClientHandler
	state                    *issuanceState
}

// KeyshareHandler is used for asking the user for his email address and PIN,
// for enrolling at a keyshare server.
type KeyshareHandler interface {
	EnrollmentError(manager irmago.SchemeManagerIdentifier, err error)
	EnrollmentSuccess(manager irmago.SchemeManagerIdentifier)
}

type ClientHandler interface {
	KeyshareHandler

	UpdateConfigurationStore(new *irmago.IrmaIdentifierSet)
	UpdateAttributes()
}

type secretKey struct {
	Key *big.Int
}

// NewClient creates a new Client that uses the directory
// specified by storagePath for (de)serializing itself. irmaConfigurationPath
// is the path to a (possibly readonly) folder containing irma_configuration;
// androidStoragePath is an optional path to the files of the old android app
// (specify "" if you do not want to parse the old android app files),
// and handler is used for informing the user of new stuff, and when a
// enrollment to a keyshare server needs to happen.
// The client returned by this function has been fully deserialized
// and is ready for use.
//
// NOTE: It is the responsibility of the caller that there exists a (properly
// protected) directory at storagePath!
func NewClient(
	storagePath string,
	irmaConfigurationPath string,
	androidStoragePath string,
	handler ClientHandler,
) (*Client, error) {
	var err error
	if err = fs.AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err = fs.AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}

	cm := &Client{
		credentials:           make(map[irmago.CredentialTypeIdentifier]map[int]*credential),
		keyshareServers:       make(map[irmago.SchemeManagerIdentifier]*keyshareServer),
		attributes:            make(map[irmago.CredentialTypeIdentifier][]*irmago.AttributeList),
		irmaConfigurationPath: irmaConfigurationPath,
		androidStoragePath:    androidStoragePath,
		handler:               handler,
	}

	cm.ConfigurationStore, err = irmago.NewConfigurationStore(storagePath+"/irma_configuration", irmaConfigurationPath)
	if err != nil {
		return nil, err
	}
	if err = cm.ConfigurationStore.ParseFolder(); err != nil {
		return nil, err
	}

	// Ensure storage path exists, and populate it with necessary files
	cm.storage = storage{storagePath: storagePath, ConfigurationStore: cm.ConfigurationStore}
	if err = cm.storage.EnsureStorageExists(); err != nil {
		return nil, err
	}

	// Perform new update functions from clientUpdates, if any
	if err = cm.update(); err != nil {
		return nil, err
	}

	// Load our stuff
	if cm.secretkey, err = cm.storage.LoadSecretKey(); err != nil {
		return nil, err
	}
	if cm.attributes, err = cm.storage.LoadAttributes(); err != nil {
		return nil, err
	}
	if cm.keyshareServers, err = cm.storage.LoadKeyshareServers(); err != nil {
		return nil, err
	}
	if cm.paillierKeyCache, err = cm.storage.LoadPaillierKeys(); err != nil {
		return nil, err
	}
	if cm.paillierKeyCache == nil {
		cm.paillierKey(false)
	}

	cm.UnenrolledSchemeManagers = cm.unenrolledSchemeManagers()
	if len(cm.UnenrolledSchemeManagers) > 1 {
		return nil, errors.New("Too many keyshare servers")
	}

	return cm, nil
}

// CredentialInfoList returns a list of information of all contained credentials.
func (client *Client) CredentialInfoList() irmago.CredentialInfoList {
	list := irmago.CredentialInfoList([]*irmago.CredentialInfo{})

	for _, attrlistlist := range client.attributes {
		for index, attrlist := range attrlistlist {
			info := attrlist.Info()
			info.Index = index
			list = append(list, info)
		}
	}

	sort.Sort(list)
	return list
}

// addCredential adds the specified credential to the Client, saving its signature
// imediately, and optionally cm.attributes as well.
func (client *Client) addCredential(cred *credential, storeAttributes bool) (err error) {
	id := cred.CredentialType().Identifier()

	// Don't add duplicate creds
	for _, attrlistlist := range client.attributes {
		for _, attrs := range attrlistlist {
			if attrs.Hash() == cred.AttributeList().Hash() {
				return nil
			}
		}
	}

	// If this is a singleton credential type, ensure we have at most one by removing any previous instance
	if cred.CredentialType().IsSingleton && len(client.creds(id)) > 0 {
		client.remove(id, 0, false) // Index is 0, because if we're here we have exactly one
	}

	// Append the new cred to our attributes and credentials
	client.attributes[id] = append(client.attrs(id), cred.AttributeList())
	if _, exists := client.credentials[id]; !exists {
		client.credentials[id] = make(map[int]*credential)
	}
	counter := len(client.attributes[id]) - 1
	client.credentials[id][counter] = cred

	if err = client.storage.StoreSignature(cred); err != nil {
		return
	}
	if storeAttributes {
		err = client.storage.StoreAttributes(client.attributes)
	}
	return
}

func generateSecretKey() (*secretKey, error) {
	key, err := gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
	if err != nil {
		return nil, err
	}
	return &secretKey{Key: key}, nil
}

// Removal methods

func (client *Client) remove(id irmago.CredentialTypeIdentifier, index int, storenow bool) error {
	// Remove attributes
	list, exists := client.attributes[id]
	if !exists || index >= len(list) {
		return errors.Errorf("Can't remove credential %s-%d: no such credential", id.String(), index)
	}
	attrs := list[index]
	client.attributes[id] = append(list[:index], list[index+1:]...)
	if storenow {
		if err := client.storage.StoreAttributes(client.attributes); err != nil {
			return err
		}
	}

	// Remove credential
	if creds, exists := client.credentials[id]; exists {
		if _, exists := creds[index]; exists {
			delete(creds, index)
			client.credentials[id] = creds
		}
	}

	// Remove signature from storage
	if err := client.storage.DeleteSignature(attrs); err != nil {
		return err
	}

	removed := map[irmago.CredentialTypeIdentifier][]irmago.TranslatedString{}
	removed[id] = attrs.Strings()

	if storenow {
		return client.addLogEntry(&LogEntry{
			Type:    actionRemoval,
			Time:    irmago.Timestamp(time.Now()),
			Removed: removed,
		})
	}
	return nil
}

func (client *Client) RemoveCredential(id irmago.CredentialTypeIdentifier, index int) error {
	return client.remove(id, index, true)
}

func (client *Client) RemoveCredentialByHash(hash string) error {
	cred, index, err := client.credentialByHash(hash)
	if err != nil {
		return err
	}
	return client.RemoveCredential(cred.CredentialType().Identifier(), index)
}

func (client *Client) RemoveAllCredentials() error {
	removed := map[irmago.CredentialTypeIdentifier][]irmago.TranslatedString{}
	for _, attrlistlist := range client.attributes {
		for _, attrs := range attrlistlist {
			if attrs.CredentialType() != nil {
				removed[attrs.CredentialType().Identifier()] = attrs.Strings()
			}
			client.storage.DeleteSignature(attrs)
		}
	}
	client.attributes = map[irmago.CredentialTypeIdentifier][]*irmago.AttributeList{}
	if err := client.storage.StoreAttributes(client.attributes); err != nil {
		return err
	}

	logentry := &LogEntry{
		Type:    actionRemoval,
		Time:    irmago.Timestamp(time.Now()),
		Removed: removed,
	}
	if err := client.addLogEntry(logentry); err != nil {
		return err
	}
	return client.storage.StoreLogs(client.logs)
}

// Attribute and credential getter methods

// attrs returns cm.attributes[id], initializing it to an empty slice if neccesary
func (client *Client) attrs(id irmago.CredentialTypeIdentifier) []*irmago.AttributeList {
	list, exists := client.attributes[id]
	if !exists {
		list = make([]*irmago.AttributeList, 0, 1)
		client.attributes[id] = list
	}
	return list
}

// creds returns cm.credentials[id], initializing it to an empty map if neccesary
func (client *Client) creds(id irmago.CredentialTypeIdentifier) map[int]*credential {
	list, exists := client.credentials[id]
	if !exists {
		list = make(map[int]*credential)
		client.credentials[id] = list
	}
	return list
}

// Attributes returns the attribute list of the requested credential, or nil if we do not have it.
func (client *Client) Attributes(id irmago.CredentialTypeIdentifier, counter int) (attributes *irmago.AttributeList) {
	list := client.attrs(id)
	if len(list) <= counter {
		return
	}
	return list[counter]
}

func (client *Client) credentialByHash(hash string) (*credential, int, error) {
	for _, attrlistlist := range client.attributes {
		for index, attrs := range attrlistlist {
			if attrs.Hash() == hash {
				cred, err := client.credential(attrs.CredentialType().Identifier(), index)
				return cred, index, err
			}
		}
	}
	return nil, 0, nil
}

func (client *Client) credentialByID(id irmago.CredentialIdentifier) (*credential, error) {
	if _, exists := client.attributes[id.Type]; !exists {
		return nil, nil
	}
	for index, attrs := range client.attributes[id.Type] {
		if attrs.Hash() == id.Hash {
			return client.credential(attrs.CredentialType().Identifier(), index)
		}
	}
	return nil, nil
}

// credential returns the requested credential, or nil if we do not have it.
func (client *Client) credential(id irmago.CredentialTypeIdentifier, counter int) (cred *credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during NewClient(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	if _, exists := client.creds(id)[counter]; !exists {
		attrs := client.Attributes(id, counter)
		if attrs == nil { // We do not have the requested cred
			return
		}
		sig, err := client.storage.LoadSignature(attrs)
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
			Attributes: append([]*big.Int{client.secretkey.Key}, attrs.Ints...),
			Signature:  sig,
			Pk:         pk,
		}, client.ConfigurationStore)
		if err != nil {
			return nil, err
		}
		client.credentials[id][counter] = cred
	}

	return client.credentials[id][counter], nil
}

// Methods used in the IRMA protocol

// Candidates returns a list of attributes present in this client
// that satisfy the specified attribute disjunction.
func (client *Client) Candidates(disjunction *irmago.AttributeDisjunction) []*irmago.AttributeIdentifier {
	candidates := make([]*irmago.AttributeIdentifier, 0, 10)

	for _, attribute := range disjunction.Attributes {
		credID := attribute.CredentialTypeIdentifier()
		if !client.ConfigurationStore.Contains(credID) {
			continue
		}
		creds := client.attributes[credID]
		count := len(creds)
		if count == 0 {
			continue
		}
		for _, attrs := range creds {
			id := &irmago.AttributeIdentifier{Type: attribute, Hash: attrs.Hash()}
			if attribute.IsCredential() {
				candidates = append(candidates, id)
			} else {
				val := attrs.UntranslatedAttribute(attribute)
				if val == "" { // This won't handle empty attributes correctly
					continue
				}
				if !disjunction.HasValues() || val == disjunction.Values[attribute] {
					candidates = append(candidates, id)
				}
			}
		}
	}

	return candidates
}

// CheckSatisfiability checks if this client has the required attributes
// to satisfy the specifed disjunction list. If not, the unsatisfiable disjunctions
// are returned.
func (client *Client) CheckSatisfiability(
	disjunctions irmago.AttributeDisjunctionList,
) ([][]*irmago.AttributeIdentifier, irmago.AttributeDisjunctionList) {
	candidates := [][]*irmago.AttributeIdentifier{}
	missing := irmago.AttributeDisjunctionList{}
	for i, disjunction := range disjunctions {
		candidates = append(candidates, []*irmago.AttributeIdentifier{})
		candidates[i] = client.Candidates(disjunction)
		if len(candidates[i]) == 0 {
			missing = append(missing, disjunction)
		}
	}
	return candidates, missing
}

func (client *Client) groupCredentials(choice *irmago.DisclosureChoice) (map[irmago.CredentialIdentifier][]int, error) {
	grouped := make(map[irmago.CredentialIdentifier][]int)
	if choice == nil || choice.Attributes == nil {
		return grouped, nil
	}

	for _, attribute := range choice.Attributes {
		identifier := attribute.Type
		ici := attribute.CredentialIdentifier()

		// If this is the first attribute of its credential type that we encounter
		// in the disclosure choice, then there is no slice yet at grouped[ici]
		if _, present := grouped[ici]; !present {
			indices := make([]int, 1, 1)
			indices[0] = 1 // Always include metadata
			grouped[ici] = indices
		}

		if identifier.IsCredential() {
			continue // In this case we only disclose the metadata attribute, which is already handled
		}
		index, err := client.ConfigurationStore.CredentialTypes[identifier.CredentialTypeIdentifier()].IndexOf(identifier)
		if err != nil {
			return nil, err
		}

		// These indices will be used in the []*big.Int at gabi.credential.Attributes,
		// which doesn't know about the secret key and metadata attribute, so +2
		grouped[ici] = append(grouped[ici], index+2)
	}

	return grouped, nil
}

// ProofBuilders constructs a list of proof builders for the specified attribute choice.
func (client *Client) ProofBuilders(choice *irmago.DisclosureChoice) (gabi.ProofBuilderList, error) {
	todisclose, err := client.groupCredentials(choice)
	if err != nil {
		return nil, err
	}

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{})
	for id, list := range todisclose {
		cred, err := client.credentialByID(id)
		if err != nil {
			return nil, err
		}
		builders = append(builders, cred.Credential.CreateDisclosureProofBuilder(list))
	}
	return builders, nil
}

// Proofs computes disclosure proofs containing the attributes specified by choice.
func (client *Client) Proofs(choice *irmago.DisclosureChoice, request irmago.IrmaSession, issig bool) (gabi.ProofList, error) {
	builders, err := client.ProofBuilders(choice)
	if err != nil {
		return nil, err
	}
	return builders.BuildProofList(request.GetContext(), request.GetNonce(), issig), nil
}

// IssuanceProofBuilders constructs a list of proof builders in the issuance protocol
// for the future credentials as well as possibly any disclosed attributes.
func (client *Client) IssuanceProofBuilders(request *irmago.IssuanceRequest) (gabi.ProofBuilderList, error) {
	state, err := newIssuanceState()
	if err != nil {
		return nil, err
	}
	client.state = state

	proofBuilders := gabi.ProofBuilderList([]gabi.ProofBuilder{})
	for _, futurecred := range request.Credentials {
		var pk *gabi.PublicKey
		pk, err = client.ConfigurationStore.PublicKey(futurecred.CredentialTypeID.IssuerIdentifier(), futurecred.KeyCounter)
		if err != nil {
			return nil, err
		}
		credBuilder := gabi.NewCredentialBuilder(
			pk, request.GetContext(), client.secretkey.Key, state.nonce2)
		state.builders = append(state.builders, credBuilder)
		proofBuilders = append(proofBuilders, credBuilder)
	}

	disclosures, err := client.ProofBuilders(request.Choice)
	if err != nil {
		return nil, err
	}
	proofBuilders = append(disclosures, proofBuilders...)
	return proofBuilders, nil
}

// IssueCommitments computes issuance commitments, along with disclosure proofs
// specified by choice.
func (client *Client) IssueCommitments(request *irmago.IssuanceRequest) (*gabi.IssueCommitmentMessage, error) {
	proofBuilders, err := client.IssuanceProofBuilders(request)
	if err != nil {
		return nil, err
	}
	list := proofBuilders.BuildProofList(request.GetContext(), request.GetNonce(), false)
	return &gabi.IssueCommitmentMessage{Proofs: list, Nonce2: client.state.nonce2}, nil
}

// ConstructCredentials constructs and saves new credentials
// using the specified issuance signature messages.
func (client *Client) ConstructCredentials(msg []*gabi.IssueSignatureMessage, request *irmago.IssuanceRequest) error {
	if len(msg) != len(client.state.builders) {
		return errors.New("Received unexpected amount of signatures")
	}

	// First collect all credentials in a slice, so that if one of them induces an error,
	// we save none of them to fail the session cleanly
	gabicreds := []*gabi.Credential{}
	for i, sig := range msg {
		attrs, err := request.Credentials[i].AttributeList(client.ConfigurationStore)
		if err != nil {
			return err
		}
		cred, err := client.state.builders[i].ConstructCredential(sig, attrs.Ints)
		if err != nil {
			return err
		}
		gabicreds = append(gabicreds, cred)
	}

	for _, gabicred := range gabicreds {
		newcred, err := newCredential(gabicred, client.ConfigurationStore)
		if err != nil {
			return err
		}
		if err = client.addCredential(newcred, true); err != nil {
			return err
		}
	}

	return nil
}

// Keyshare server handling

// PaillierKey returns a new Paillier key (and generates a new one in a goroutine).
func (client *Client) paillierKey(wait bool) *paillierPrivateKey {
	cached := client.paillierKeyCache
	ch := make(chan bool)

	// Would just write client.paillierKeyCache instead of cached here, but the worker
	// modifies client.paillierKeyCache, and we must be sure that the boolean here and
	// the if-clause below match.
	go client.paillierKeyWorker(cached == nil && wait, ch)
	if cached == nil && wait {
		<-ch
		// generate yet another one for future calls, but no need to wait now
		go client.paillierKeyWorker(false, ch)
	}
	return client.paillierKeyCache
}

func (client *Client) paillierKeyWorker(wait bool, ch chan bool) {
	newkey, _ := paillier.GenerateKey(rand.Reader, 2048)
	client.paillierKeyCache = (*paillierPrivateKey)(newkey)
	client.storage.StorePaillierKeys(client.paillierKeyCache)
	if wait {
		ch <- true
	}
}

func (client *Client) unenrolledSchemeManagers() []irmago.SchemeManagerIdentifier {
	list := []irmago.SchemeManagerIdentifier{}
	for name, manager := range client.ConfigurationStore.SchemeManagers {
		if _, contains := client.keyshareServers[name]; manager.Distributed() && !contains {
			list = append(list, manager.Identifier())
		}
	}
	return list
}

// KeyshareEnroll attempts to enroll at the keyshare server of the specified scheme manager.
func (client *Client) KeyshareEnroll(manager irmago.SchemeManagerIdentifier, email, pin string) {
	go func() {
		defer func() {
			handlePanic(func(err *irmago.SessionError) {
				if client.handler != nil {
					client.handler.EnrollmentError(manager, err)
				}
			})
		}()

		err := client.keyshareEnrollWorker(manager, email, pin)
		client.UnenrolledSchemeManagers = client.unenrolledSchemeManagers()
		if err != nil {
			client.handler.EnrollmentError(manager, err)
		} else {
			client.handler.EnrollmentSuccess(manager)
		}
	}()

}

func (client *Client) keyshareEnrollWorker(managerID irmago.SchemeManagerIdentifier, email, pin string) error {
	manager, ok := client.ConfigurationStore.SchemeManagers[managerID]
	if !ok {
		return errors.New("Unknown scheme manager")
	}
	if len(manager.KeyshareServer) == 0 {
		return errors.New("Scheme manager has no keyshare server")
	}
	if len(pin) < 5 {
		return errors.New("PIN too short, must be at least 5 characters")
	}

	transport := irmago.NewHTTPTransport(manager.KeyshareServer)
	kss, err := newKeyshareServer(client.paillierKey(true), manager.KeyshareServer, email)
	if err != nil {
		return err
	}
	message := keyshareEnrollment{
		Username:  email,
		Pin:       kss.HashedPin(pin),
		PublicKey: (*paillierPublicKey)(&kss.PrivateKey.PublicKey),
	}

	result := &struct{}{}
	err = transport.Post("web/users/selfenroll", result, message)
	if err != nil {
		return err
	}

	client.keyshareServers[managerID] = kss
	return client.storage.StoreKeyshareServers(client.keyshareServers)
}

// KeyshareRemove unenrolls the keyshare server of the specified scheme manager.
func (client *Client) KeyshareRemove(manager irmago.SchemeManagerIdentifier) error {
	if _, contains := client.keyshareServers[manager]; !contains {
		return errors.New("Can't uninstall unknown keyshare server")
	}
	delete(client.keyshareServers, manager)
	return client.storage.StoreKeyshareServers(client.keyshareServers)
}

func (client *Client) KeyshareRemoveAll() error {
	client.keyshareServers = map[irmago.SchemeManagerIdentifier]*keyshareServer{}
	client.UnenrolledSchemeManagers = client.unenrolledSchemeManagers()
	return client.storage.StoreKeyshareServers(client.keyshareServers)
}

// Add, load and store log entries

func (client *Client) addLogEntry(entry *LogEntry) error {
	client.logs = append(client.logs, entry)
	return client.storage.StoreLogs(client.logs)
	return nil
}

func (client *Client) Logs() ([]*LogEntry, error) {
	if client.logs == nil || len(client.logs) == 0 {
		var err error
		client.logs, err = client.storage.LoadLogs()
		if err != nil {
			return nil, err
		}
	}
	return client.logs, nil
}
