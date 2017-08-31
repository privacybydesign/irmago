package irmago

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io/ioutil"
	"math/big"

	"github.com/mhe/gabi"
)

// Manager is the global instance of CredentialManager.
var Manager = newCredentialManager()

// CredentialManager manages credentials.
type CredentialManager struct {
	secretkey   *big.Int
	storagePath string
	attributes  map[CredentialTypeIdentifier][]*AttributeList
	credentials map[CredentialTypeIdentifier]map[int]*Credential
}

func newCredentialManager() *CredentialManager {
	return &CredentialManager{
		credentials: make(map[CredentialTypeIdentifier]map[int]*Credential),
	}
}

func (cm *CredentialManager) generateSecretKey() (sk *big.Int, err error) {
	return gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
}

// Init deserializes the credentials from storage.
func (cm *CredentialManager) Init(path string) (err error) {
	cm.storagePath = path

	err = cm.ensureStorageExists()
	if err != nil {
		return err
	}
	cm.secretkey, err = cm.loadSecretKey()
	if err != nil {
		return
	}
	cm.attributes, err = cm.loadAttributes()
	return

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
func (cm *CredentialManager) creds(id CredentialTypeIdentifier) map[int]*Credential {
	list, exists := cm.credentials[id]
	if !exists {
		list = make(map[int]*Credential)
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

func (cm *CredentialManager) CredentialByID(id CredentialIdentifier) (cred *Credential, err error) {
	return cm.Credential(id.Type, id.Index)
}

// Credential returns the requested credential, or nil if we do not have it.
func (cm *CredentialManager) Credential(id CredentialTypeIdentifier, counter int) (cred *Credential, err error) {
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

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance,
// and saving them to storage.
// CAREFUL: this method overwrites any existing secret keys and attributes on storage.
func (cm *CredentialManager) ParseAndroidStorage() (err error) {
	exists, err := PathExists(cm.path(cardemuXML))
	if err != nil || !exists {
		return
	}

	bytes, err := ioutil.ReadFile(cm.path(cardemuXML))
	parsedxml := struct {
		Strings []struct {
			Name    string `xml:"name,attr"`
			Content string `xml:",chardata"`
		} `xml:"string"`
	}{}
	xml.Unmarshal(bytes, &parsedxml)

	parsedjson := make(map[string][]*gabi.Credential)
	for _, xmltag := range parsedxml.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedjson); err != nil {
				return
			}
		}
	}

	for _, list := range parsedjson {
		cm.secretkey = list[0].Attributes[0]
		for i, gabicred := range list {
			cred := newCredential(gabicred)
			if cred.CredentialType() == nil {
				return errors.New("cannot add unknown credential type")
			}

			cm.addCredential(cred)
			err = cm.storeSignature(cred, i)
			if err != nil {
				return err
			}
		}
	}

	if len(cm.credentials) > 0 {
		err = cm.storeAttributes()
		if err != nil {
			return err
		}
		err = cm.storeSecretKey(cm.secretkey)
		if err != nil {
			return err
		}
	}

	return
}

func (cm *CredentialManager) addCredential(cred *Credential) {
	id := cred.CredentialType().Identifier()
	cm.attributes[id] = append(cm.attrs(id), NewAttributeListFromInts(cred.Attributes[1:]))

	if _, exists := cm.credentials[id]; !exists {
		cm.credentials[id] = make(map[int]*Credential)
	}
	counter := len(cm.attributes[id]) - 1
	cm.credentials[id][counter] = cred
}

// Add adds the specified credential to the CredentialManager.
func (cm *CredentialManager) Add(cred *Credential) (err error) {
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

func (cm *CredentialManager) CheckSatisfiability(disjunctions DisjunctionListContainer) AttributeDisjunctionList {
	missing := make(AttributeDisjunctionList, 0, 5)
	for _, disjunction := range disjunctions.DisjunctionList() {
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

		// These indices will be used in the []*big.Int at gabi.Credential.Attributes,
		// which doesn't know about the secret key and metadata attribute, so +2
		grouped[ici] = append(grouped[ici], index+2)
	}

	return grouped, nil
}

type Session interface {
	GetNonce() *big.Int
	GetContext() *big.Int
}

func (cm *CredentialManager) proofsBuilders(choice *DisclosureChoice) ([]gabi.ProofBuilder, error) {
	todisclose, err := cm.groupCredentials(choice)
	if err != nil {
		return nil, err
	}

	builders := []gabi.ProofBuilder{}
	for id, list := range todisclose {
		cred, err := cm.CredentialByID(id)
		if err != nil {
			return nil, err
		}
		builders = append(builders, cred.Credential.CreateDisclosureProofBuilder(list))
	}
	return builders, nil
}

func (cm *CredentialManager) Proofs(choice *DisclosureChoice, request Session, issig bool) (gabi.ProofList, error) {
	builders, err := cm.proofsBuilders(choice)
	if err != nil {
		return nil, err
	}
	return gabi.BuildProofList(request.GetContext(), request.GetNonce(), builders, issig), nil
}

func (cm *CredentialManager) IssueCommitments(choice *DisclosureChoice, request *IssuanceRequest) (*gabi.IssueCommitmentMessage, error) {
	state, err := newIssuanceState(request)
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
		cm.Add(newCredential(cred))
	}

	return nil
}
