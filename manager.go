package irmago

import (
	"crypto/rand"
	"math/big"
	"sort"
	"time"

	"github.com/credentials/go-go-gadget-paillier"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// This file contains most methods of the CredentialManager (c.f. session.go
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

// CredentialManager (de)serializes credentials and keyshare server information
// from storage; as well as logs of earlier IRMA sessions; it provides access
// to the attributes and all related information of its credentials;
// it is the starting point for new IRMA sessions; and it computes some
// of the messages in the client side of the IRMA protocol.
type CredentialManager struct {
	// Stuff we manage on disk
	secretkey        *secretKey
	attributes       map[CredentialTypeIdentifier][]*AttributeList
	credentials      map[CredentialTypeIdentifier]map[int]*credential
	keyshareServers  map[SchemeManagerIdentifier]*keyshareServer
	paillierKeyCache *paillierPrivateKey
	logs             []*LogEntry
	updates          []update

	// Where we store/load it to/from
	storage storage

	// Other state
	ConfigurationStore    *ConfigurationStore
	irmaConfigurationPath string
	androidStoragePath    string
	keyshareHandler       KeyshareHandler
}

type secretKey struct {
	Key *big.Int
}

// NewCredentialManager creates a new CredentialManager that uses the directory
// specified by storagePath for (de)serializing itself. irmaConfigurationPath
// is the path to a (possibly readonly) folder containing irma_configuration;
// androidStoragePath is an optional path to the files of the old android app
// (specify "" if you do not want to parse the old android app files),
// and keyshareHandler is used for when a registration to a keyshare server needs
// to happen.
// The credential manager returned by this function has been fully deserialized
// and is ready for use.
//
// NOTE: It is the responsibility of the caller that there exists a (properly
// protected) directory at storagePath!
func NewCredentialManager(
	storagePath string,
	irmaConfigurationPath string,
	androidStoragePath string,
	keyshareHandler KeyshareHandler,
) (*CredentialManager, error) {
	var err error
	if err = AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err = AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}

	cm := &CredentialManager{
		credentials:           make(map[CredentialTypeIdentifier]map[int]*credential),
		keyshareServers:       make(map[SchemeManagerIdentifier]*keyshareServer),
		attributes:            make(map[CredentialTypeIdentifier][]*AttributeList),
		irmaConfigurationPath: irmaConfigurationPath,
		androidStoragePath:    androidStoragePath,
		keyshareHandler:       keyshareHandler,
	}

	cm.ConfigurationStore, err = NewConfigurationStore(storagePath+"/irma_configuration", irmaConfigurationPath)
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

	// Perform new update functions from credentialManagerUpdates, if any
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
	if cm.paillierKeyCache, err = cm.storage.LoadPaillierKeys(); err != nil {
		return nil, err
	}
	if cm.keyshareServers, err = cm.storage.LoadKeyshareServers(); err != nil {
		return nil, err
	}

	unenrolled := cm.unenrolledKeyshareServers()
	switch len(unenrolled) {
	case 0: // nop
	case 1:
		if keyshareHandler == nil {
			return nil, errors.New("Keyshare server found but no KeyshareHandler was given")
		}
		cm.KeyshareEnroll(unenrolled[0], keyshareHandler)
	default:
		return nil, errors.New("Too many keyshare servers")
	}

	return cm, nil
}

// CredentialInfoList returns a list of information of all contained credentials.
func (cm *CredentialManager) CredentialInfoList() CredentialInfoList {
	list := CredentialInfoList([]*CredentialInfo{})

	for _, attrlistlist := range cm.attributes {
		for index, attrlist := range attrlistlist {
			info := attrlist.Info()
			info.Index = index
			list = append(list, info)
		}
	}

	sort.Sort(list)
	return list
}

// addCredential adds the specified credential to the CredentialManager, saving its signature
// imediately, and optionally cm.attributes as well.
func (cm *CredentialManager) addCredential(cred *credential, storeAttributes bool) (err error) {
	id := cred.CredentialType().Identifier()
	cm.attributes[id] = append(cm.attrs(id), cred.AttributeList())

	if _, exists := cm.credentials[id]; !exists {
		cm.credentials[id] = make(map[int]*credential)
	}
	if cred.CredentialType().IsSingleton {
		cm.credentials[id][0] = cred
	} else {
		counter := len(cm.attributes[id]) - 1
		cm.credentials[id][counter] = cred
	}

	if err = cm.storage.StoreSignature(cred); err != nil {
		return
	}
	if storeAttributes {
		err = cm.storage.StoreAttributes(cm.attributes)
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

func (cm *CredentialManager) remove(id CredentialTypeIdentifier, index int, storenow bool) error {
	// Remove attributes
	list, exists := cm.attributes[id]
	if !exists || index >= len(list) {
		return errors.Errorf("Can't remove credential %s-%d: no such credential", id.String(), index)
	}
	attrs := list[index]
	cm.attributes[id] = append(list[:index], list[index+1:]...)
	if storenow {
		if err := cm.storage.StoreAttributes(cm.attributes); err != nil {
			return err
		}
	}

	// Remove credential
	if creds, exists := cm.credentials[id]; exists {
		if _, exists := creds[index]; exists {
			creds[index] = nil
			cm.credentials[id] = creds
		}
	}

	// Remove signature from storage
	if err := cm.storage.DeleteSignature(attrs); err != nil {
		return err
	}

	removed := map[CredentialTypeIdentifier][]TranslatedString{}
	removed[id] = attrs.Strings()

	if storenow {
		return cm.addLogEntry(&LogEntry{
			Type:    actionRemoval,
			Time:    Timestamp(time.Now()),
			Removed: removed,
		})
	}
	return nil
}

func (cm *CredentialManager) RemoveCredential(id CredentialTypeIdentifier, index int) error {
	return cm.remove(id, index, true)
}

func (cm *CredentialManager) RemoveCredentialByHash(hash string) error {
	cred, index, err := cm.credentialByHash(hash)
	if err != nil {
		return err
	}
	return cm.RemoveCredential(cred.CredentialType().Identifier(), index)
}

func (cm *CredentialManager) RemoveAllCredentials() error {
	removed := map[CredentialTypeIdentifier][]TranslatedString{}
	list := cm.CredentialInfoList()
	for _, cred := range list {
		id := NewCredentialTypeIdentifier(cred.ID)
		removed[id] = cred.Attributes
		if err := cm.remove(id, cred.Index, false); err != nil {
			return err
		}
	}
	if err := cm.storage.StoreAttributes(cm.attributes); err != nil {
		return err
	}

	logentry := &LogEntry{
		Type:    actionRemoval,
		Time:    Timestamp(time.Now()),
		Removed: removed,
	}
	if err := cm.addLogEntry(logentry); err != nil {
		return err
	}
	return cm.storage.StoreLogs(cm.logs)
}

// Attribute and credential getter methods

// attrs returns cm.attributes[id], initializing it to an empty slice if neccesary
func (cm *CredentialManager) attrs(id CredentialTypeIdentifier) []*AttributeList {
	list, exists := cm.attributes[id]
	if !exists {
		list = make([]*AttributeList, 0, 1)
		cm.attributes[id] = list
	}
	return list
}

// creds returns cm.credentials[id], initializing it to an empty map if neccesary
func (cm *CredentialManager) creds(id CredentialTypeIdentifier) map[int]*credential {
	list, exists := cm.credentials[id]
	if !exists {
		list = make(map[int]*credential)
		cm.credentials[id] = list
	}
	return list
}

// Attributes returns the attribute list of the requested credential, or nil if we do not have it.
func (cm *CredentialManager) Attributes(id CredentialTypeIdentifier, counter int) (attributes *AttributeList) {
	list := cm.attrs(id)
	if len(list) <= counter {
		return
	}
	return list[counter]
}

func (cm *CredentialManager) credentialByHash(hash string) (*credential, int, error) {
	for _, attrlistlist := range cm.attributes {
		for index, attrs := range attrlistlist {
			if attrs.hash() == hash {
				cred, err := cm.credential(attrs.CredentialType().Identifier(), index)
				return cred, index, err
			}
		}
	}
	return nil, 0, nil
}

func (cm *CredentialManager) credentialByID(id CredentialIdentifier) (*credential, error) {
	return cm.credential(id.Type, id.Index)
}

// credential returns the requested credential, or nil if we do not have it.
func (cm *CredentialManager) credential(id CredentialTypeIdentifier, counter int) (cred *credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during NewCredentialManager(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	if _, exists := cm.creds(id)[counter]; !exists {
		attrs := cm.Attributes(id, counter)
		if attrs == nil { // We do not have the requested cred
			return
		}
		sig, err := cm.storage.LoadSignature(attrs)
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
			Attributes: append([]*big.Int{cm.secretkey.Key}, attrs.Ints...),
			Signature:  sig,
			Pk:         pk,
		}, cm.ConfigurationStore)
		if err != nil {
			return nil, err
		}
		cm.credentials[id][counter] = cred
	}

	return cm.credentials[id][counter], nil
}

// Methods used in the IRMA protocol

// Candidates returns a list of attributes present in this credential manager
// that satisfy the specified attribute disjunction.
func (cm *CredentialManager) Candidates(disjunction *AttributeDisjunction) []*AttributeIdentifier {
	candidates := make([]*AttributeIdentifier, 0, 10)

	for _, attribute := range disjunction.Attributes {
		credID := attribute.CredentialTypeIdentifier()
		if !cm.ConfigurationStore.Contains(credID) {
			continue
		}
		creds := cm.credentials[credID]
		count := len(creds)
		if count == 0 {
			continue
		}
		for i, cred := range creds {
			id := &AttributeIdentifier{Type: attribute, Index: i, Count: count}
			if attribute.IsCredential() {
				candidates = append(candidates, id)
			} else {
				attrs := cred.AttributeList()
				val := attrs.untranslatedAttribute(attribute)
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

// CheckSatisfiability checks if this credential manager has the required attributes
// to satisfy the specifed disjunction list. If not, the unsatisfiable disjunctions
// are returned.
func (cm *CredentialManager) CheckSatisfiability(disjunctions AttributeDisjunctionList) AttributeDisjunctionList {
	missing := make(AttributeDisjunctionList, 0, 5)
	for _, disjunction := range disjunctions {
		if len(cm.Candidates(disjunction)) == 0 {
			missing = append(missing, disjunction)
		}
	}

	return missing
}

func (cm *CredentialManager) groupCredentials(choice *DisclosureChoice) (map[CredentialIdentifier][]int, error) {
	grouped := make(map[CredentialIdentifier][]int)

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
		index, err := cm.ConfigurationStore.CredentialTypes[identifier.CredentialTypeIdentifier()].IndexOf(identifier)
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
func (cm *CredentialManager) ProofBuilders(choice *DisclosureChoice) (gabi.ProofBuilderList, error) {
	todisclose, err := cm.groupCredentials(choice)
	if err != nil {
		return nil, err
	}

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{})
	for id, list := range todisclose {
		cred, err := cm.credentialByID(id)
		if err != nil {
			return nil, err
		}
		builders = append(builders, cred.Credential.CreateDisclosureProofBuilder(list))
	}
	return builders, nil
}

// Proofs computes disclosure proofs containing the attributes specified by choice.
func (cm *CredentialManager) Proofs(choice *DisclosureChoice, request IrmaSession, issig bool) (gabi.ProofList, error) {
	builders, err := cm.ProofBuilders(choice)
	if err != nil {
		return nil, err
	}
	return builders.BuildProofList(request.GetContext(), request.GetNonce(), issig), nil
}

// IssuanceProofBuilders constructs a list of proof builders in the issuance protocol
// for the future credentials as well as possibly any disclosed attributes.
func (cm *CredentialManager) IssuanceProofBuilders(request *IssuanceRequest) (gabi.ProofBuilderList, error) {
	state, err := newIssuanceState()
	if err != nil {
		return nil, err
	}
	request.state = state

	proofBuilders := gabi.ProofBuilderList([]gabi.ProofBuilder{})
	for _, futurecred := range request.Credentials {
		var pk *gabi.PublicKey
		pk, err = cm.ConfigurationStore.PublicKey(futurecred.Credential.IssuerIdentifier(), futurecred.KeyCounter)
		if err != nil {
			return nil, err
		}
		credBuilder := gabi.NewCredentialBuilder(
			pk, request.GetContext(), cm.secretkey.Key, state.nonce2)
		request.state.builders = append(request.state.builders, credBuilder)
		proofBuilders = append(proofBuilders, credBuilder)
	}

	disclosures, err := cm.ProofBuilders(request.choice)
	if err != nil {
		return nil, err
	}
	proofBuilders = append(disclosures, proofBuilders...)
	return proofBuilders, nil
}

// IssueCommitments computes issuance commitments, along with disclosure proofs
// specified by choice.
func (cm *CredentialManager) IssueCommitments(request *IssuanceRequest) (*gabi.IssueCommitmentMessage, error) {
	proofBuilders, err := cm.IssuanceProofBuilders(request)
	if err != nil {
		return nil, err
	}
	list := proofBuilders.BuildProofList(request.GetContext(), request.GetNonce(), false)
	return &gabi.IssueCommitmentMessage{Proofs: list, Nonce2: request.state.nonce2}, nil
}

// ConstructCredentials constructs and saves new credentials
// using the specified issuance signature messages.
func (cm *CredentialManager) ConstructCredentials(msg []*gabi.IssueSignatureMessage, request *IssuanceRequest) error {
	if len(msg) != len(request.state.builders) {
		return errors.New("Received unexpected amount of signatures")
	}

	// First collect all credentials in a slice, so that if one of them induces an error,
	// we save none of them to fail the session cleanly
	gabicreds := []*gabi.Credential{}
	for i, sig := range msg {
		attrs, err := request.Credentials[i].AttributeList(cm.ConfigurationStore)
		if err != nil {
			return err
		}
		cred, err := request.state.builders[i].ConstructCredential(sig, attrs.Ints)
		if err != nil {
			return err
		}
		gabicreds = append(gabicreds, cred)
	}

	for _, gabicred := range gabicreds {
		newcred, err := newCredential(gabicred, cm.ConfigurationStore)
		if err != nil {
			return err
		}
		if err = cm.addCredential(newcred, true); err != nil {
			return err
		}
	}

	return nil
}

// Keyshare server handling

// PaillierKey returns a new Paillier key (and generates a new one in a goroutine).
func (cm *CredentialManager) paillierKey(wait bool) *paillierPrivateKey {
	cached := cm.paillierKeyCache
	ch := make(chan bool)
	go func() {
		newkey, _ := paillier.GenerateKey(rand.Reader, 2048)
		cm.paillierKeyCache = (*paillierPrivateKey)(newkey)
		if wait && cached == nil {
			ch <- true
		}
	}()
	if wait && cached == nil {
		<-ch
	}
	return cm.paillierKeyCache
}

func (cm *CredentialManager) unenrolledKeyshareServers() []*SchemeManager {
	list := []*SchemeManager{}
	for name, manager := range cm.ConfigurationStore.SchemeManagers {
		if _, contains := cm.keyshareServers[name]; len(manager.KeyshareServer) > 0 && !contains {
			list = append(list, manager)
		}
	}
	return list
}

// KeyshareEnroll attempts to register at the keyshare server of the specified scheme manager.
func (cm *CredentialManager) KeyshareEnroll(manager *SchemeManager, handler KeyshareHandler) {
	handler.StartRegistration(manager, func(email, pin string) {
		go func() {
			err := cm.keyshareEnrollWorker(manager.Identifier(), email, pin)
			if err != nil {
				handler.RegistrationError(err)
			} else {
				handler.RegistrationSuccess()
			}
		}()
	})
}

func (cm *CredentialManager) keyshareEnrollWorker(managerID SchemeManagerIdentifier, email, pin string) error {
	manager, ok := cm.ConfigurationStore.SchemeManagers[managerID]
	if !ok {
		return errors.New("Unknown scheme manager")
	}
	if len(manager.KeyshareServer) == 0 {
		return errors.New("Scheme manager has no keyshare server")
	}
	if len(pin) < 5 {
		return errors.New("PIN too short, must be at least 5 characters")
	}

	transport := NewHTTPTransport(manager.KeyshareServer)
	kss, err := newKeyshareServer(cm.paillierKey(true), manager.KeyshareServer, email)
	if err != nil {
		return err
	}
	message := keyshareRegistration{
		Username:  email,
		Pin:       kss.HashedPin(pin),
		PublicKey: (*paillierPublicKey)(&kss.PrivateKey.PublicKey),
	}

	result := &struct{}{}
	err = transport.Post("web/users/selfenroll", result, message)
	if err != nil {
		return err
	}

	cm.keyshareServers[managerID] = kss
	return cm.storage.StoreKeyshareServers(cm.keyshareServers)
}

// KeyshareRemove unregisters the keyshare server of the specified scheme manager.
func (cm *CredentialManager) KeyshareRemove(manager SchemeManagerIdentifier) error {
	if _, contains := cm.keyshareServers[manager]; !contains {
		return errors.New("Can't uninstall unknown keyshare server")
	}
	delete(cm.keyshareServers, manager)
	return cm.storage.StoreKeyshareServers(cm.keyshareServers)
}

// Add, load and store log entries

func (cm *CredentialManager) addLogEntry(entry *LogEntry) error {
	cm.logs = append(cm.logs, entry)
	return cm.storage.StoreLogs(cm.logs)
	return nil
}

func (cm *CredentialManager) Logs() ([]*LogEntry, error) {
	if cm.logs == nil || len(cm.logs) == 0 {
		var err error
		cm.logs, err = cm.storage.LoadLogs()
		if err != nil {
			return nil, err
		}
	}
	return cm.logs, nil
}
