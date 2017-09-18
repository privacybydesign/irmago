package irmago

import (
	"errors"
	"math/big"

	"crypto/rand"

	"sort"

	"github.com/credentials/go-go-gadget-paillier"
	"github.com/mhe/gabi"
)

// Manager is the global instance of CredentialManager.
var Manager = newCredentialManager()

// CredentialManager manages credentials.
type CredentialManager struct {
	secretkey       *big.Int
	storagePath     string
	attributes      map[CredentialTypeIdentifier][]*AttributeList
	credentials     map[CredentialTypeIdentifier]map[int]*credential
	keyshareServers map[SchemeManagerIdentifier]*keyshareServer

	paillierKeyCache *paillierPrivateKey
}

func newCredentialManager() *CredentialManager {
	return &CredentialManager{
		credentials:     make(map[CredentialTypeIdentifier]map[int]*credential),
		keyshareServers: make(map[SchemeManagerIdentifier]*keyshareServer),
	}
}

func (cm *CredentialManager) CredentialList() CredentialList {
	list := CredentialList([]*Credential{})
	for _, credlist := range cm.credentials {
		for _, cred := range credlist {
			list = append(list, cred.info)
		}
	}
	sort.Sort(list)
	return list
}

func (cm *CredentialManager) generateSecretKey() (sk *big.Int, err error) {
	return gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
}

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

func (cm *CredentialManager) credentialByID(id CredentialIdentifier) (cred *credential, err error) {
	return cm.credential(id.Type, id.Index)
}

// credential returns the requested credential, or nil if we do not have it.
func (cm *CredentialManager) credential(id CredentialTypeIdentifier, counter int) (cred *credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during Init(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	if _, exists := cm.creds(id)[counter]; !exists {
		attrs := cm.Attributes(id, counter)
		if attrs == nil { // We do not have the requested cred
			return
		}
		ints := append([]*big.Int{cm.secretkey}, attrs.Ints...)
		sig, err := cm.loadSignature(id, counter)
		if err != nil {
			return nil, err
		}
		if sig == nil {
			err = errors.New("signature file not found")
			return nil, err
		}
		meta := MetadataFromInt(ints[1])
		pk := meta.PublicKey()
		if pk == nil {
			return nil, errors.New("unknown public key")
		}
		cred := newCredential(&gabi.Credential{
			Attributes: ints,
			Signature:  sig,
			Pk:         pk,
		})
		cm.credentials[id][counter] = cred
	}

	return cm.credentials[id][counter], nil
}

func (cm *CredentialManager) addCredential(cred *credential) {
	id := cred.CredentialType().Identifier()
	cm.attributes[id] = append(cm.attrs(id), NewAttributeListFromInts(cred.Attributes[1:]))

	if _, exists := cm.credentials[id]; !exists {
		cm.credentials[id] = make(map[int]*credential)
	}
	counter := len(cm.attributes[id]) - 1
	cm.credentials[id][counter] = cred
}

// add adds the specified credential to the CredentialManager.
func (cm *CredentialManager) add(cred *credential) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	cm.addCredential(cred)
	counter := len(cm.credentials[cred.CredentialType().Identifier()]) - 1

	err = cm.storeSignature(cred, counter)
	if err != nil {
		return
	}
	err = cm.storeAttributes()
	return
}

// Candidates returns a list of attributes present in this credential manager
// that satisfy the specified attribute disjunction.
func (cm *CredentialManager) Candidates(disjunction *AttributeDisjunction) []*AttributeIdentifier {
	candidates := make([]*AttributeIdentifier, 0, 10)

	for _, attribute := range disjunction.Attributes {
		credID := attribute.CredentialTypeIdentifier()
		if !MetaStore.Contains(credID) {
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
				attrs := NewAttributeListFromInts(cred.Attributes[1:])
				val := attrs.Attribute(attribute)
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
		index, err := MetaStore.Credentials[identifier.CredentialTypeIdentifier()].IndexOf(identifier)
		if err != nil {
			return nil, err
		}

		// These indices will be used in the []*big.Int at gabi.credential.Attributes,
		// which doesn't know about the secret key and metadata attribute, so +2
		grouped[ici] = append(grouped[ici], index+2)
	}

	return grouped, nil
}

// Session is an IRMA session.
type Session interface {
	GetNonce() *big.Int
	SetNonce(*big.Int)
	GetContext() *big.Int
	SetContext(*big.Int)
	DisjunctionList() AttributeDisjunctionList
}

func (cm *CredentialManager) proofsBuilders(choice *DisclosureChoice) ([]gabi.ProofBuilder, error) {
	todisclose, err := cm.groupCredentials(choice)
	if err != nil {
		return nil, err
	}

	builders := []gabi.ProofBuilder{}
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
func (cm *CredentialManager) Proofs(choice *DisclosureChoice, request Session, issig bool) (gabi.ProofList, error) {
	builders, err := cm.proofsBuilders(choice)
	if err != nil {
		return nil, err
	}
	return gabi.BuildProofList(request.GetContext(), request.GetNonce(), builders, issig), nil
}

// IssueCommitments computes issuance commitments, along with disclosure proofs
// specified by choice.
func (cm *CredentialManager) IssueCommitments(choice *DisclosureChoice, request *IssuanceRequest) (*gabi.IssueCommitmentMessage, error) {
	state, err := newIssuanceState()
	if err != nil {
		return nil, err
	}
	request.state = state

	proofBuilders := []gabi.ProofBuilder{}
	for _, futurecred := range request.Credentials {
		pk := MetaStore.PublicKey(futurecred.Credential.IssuerIdentifier(), futurecred.KeyCounter)
		credBuilder := gabi.NewCredentialBuilder(pk, request.GetContext(), cm.secretkey, state.nonce2)
		request.state.builders = append(request.state.builders, credBuilder)
		proofBuilders = append(proofBuilders, credBuilder)
	}

	disclosures, err := cm.proofsBuilders(choice)
	if err != nil {
		return nil, err
	}
	proofBuilders = append(disclosures, proofBuilders...)

	list := gabi.BuildProofList(request.GetContext(), request.GetNonce(), proofBuilders, false)
	return &gabi.IssueCommitmentMessage{Proofs: list, Nonce2: state.nonce2}, nil
}

// ConstructCredentials constructs and saves new credentials
// using the specified issuance signature messages.
func (cm *CredentialManager) ConstructCredentials(msg []*gabi.IssueSignatureMessage, request *IssuanceRequest) error {
	if len(msg) != len(request.state.builders) {
		return errors.New("Received unexpected amount of signatures")
	}

	// First collect all credentials in a slice, so that if one of them induces an error,
	// we save none of them to fail the session cleanly
	creds := []*gabi.Credential{}
	for i, sig := range msg {
		attrs, err := request.Credentials[i].AttributeList()
		if err != nil {
			return err
		}
		cred, err := request.state.builders[i].ConstructCredential(sig, attrs.Ints)
		if err != nil {
			return err
		}
		creds = append(creds, cred)
	}

	for _, cred := range creds {
		cm.add(newCredential(cred))
	}

	return nil
}

// PaillierKey returns a new Paillier key (and generates a new one in a goroutine).
func (cm *CredentialManager) paillierKey() *paillierPrivateKey {
	retval := cm.paillierKeyCache
	go func() {
		newkey, _ := paillier.GenerateKey(rand.Reader, 2048)
		converted := paillierPrivateKey(*newkey)
		cm.paillierKeyCache = &converted
	}()
	return retval
}

func (cm *CredentialManager) unenrolledKeyshareServers() []*SchemeManager {
	list := []*SchemeManager{}
	for name, manager := range MetaStore.SchemeManagers {
		if _, contains := cm.keyshareServers[name]; len(manager.KeyshareServer) > 0 && !contains {
			list = append(list, manager)
		}
	}
	return list
}

func (cm *CredentialManager) KeyshareEnroll(managerId SchemeManagerIdentifier, email, pin string) error {
	manager, ok := MetaStore.SchemeManagers[managerId]
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
	kss, err := newKeyshareServer(Manager.paillierKey(), manager.URL, email)
	if err != nil {
		return err
	}
	message := keyshareRegistration{
		Username:  email,
		Pin:       kss.HashedPin(pin),
		PublicKey: (*paillierPublicKey)(&kss.PrivateKey.PublicKey),
	}

	// TODO: examine error returned by Post() to see if it tells us that the email address is already in use
	result := &struct{}{}
	err = transport.Post("web/users/selfenroll", result, message)
	if err != nil {
		return err
	}

	cm.keyshareServers[managerId] = kss
	return cm.storeKeyshareServers()
}

func (cm *CredentialManager) KeyshareRemove(manager SchemeManagerIdentifier) error {
	if _, contains := cm.keyshareServers[manager]; !contains {
		return errors.New("Can't uninstall unknown keyshare server")
	}
	delete(cm.keyshareServers, manager)
	return cm.storeKeyshareServers()
}
