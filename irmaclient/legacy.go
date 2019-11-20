package irmaclient

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
)

// This file contains the legacy storage based on files. These functions are needed
// in the upgrade path to convert the file based storage to the bbolt based storage.
// The new storage functions for bbolt can be found in storage.go.

type fileStorage struct {
	storagePath   string
	Configuration *irma.Configuration
}

// Legacy filenames in which we stored stuff
const (
	skFile          = "sk"
	attributesFile  = "attrs"
	kssFile         = "kss"
	updatesFile     = "updates"
	logsFile        = "logs"
	preferencesFile = "preferences"
	signaturesDir   = "sigs"
)

func (f *fileStorage) path(p string) string {
	return filepath.Join(f.storagePath, p)
}

func (f *fileStorage) load(dest interface{}, path string) (err error) {
	exists, err := fs.PathExists(f.path(path))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(f.path(path))
	if err != nil {
		return
	}
	return json.Unmarshal(bytes, dest)
}

func (f *fileStorage) signatureFilename(attrs *irma.AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return filepath.Join(signaturesDir, attrs.Hash())
}

func (f *fileStorage) LoadSignature(attrs *irma.AttributeList) (signature *gabi.CLSignature, witness *revocation.Witness, err error) {
	sigpath := s.signatureFilename(attrs)
	if err := fs.AssertPathExists(s.path(sigpath)); err != nil {
		return nil, nil, err
	}
	sig := &clSignatureWitness{}
	if err := s.loadFromFile(sig, sigpath); err != nil {
		return nil, nil, err
	}
	return sig.CLSignature, sig.Witness, nil
}

// LoadSecretKey retrieves and returns the secret key from file storage. When no secret key
// file is found, nil is returned.
func (f *fileStorage) LoadSecretKey() (*secretKey, error) {
	var err error
	sk := &secretKey{}
	if err = f.load(sk, skFile); err != nil {
		return nil, err
	}
	if sk.Key != nil {
		return sk, nil
	}
	return nil, nil
}

func (f *fileStorage) LoadAttributes() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
	// The attributes are stored as a list of instances of AttributeList
	temp := []*irma.AttributeList{}
	if err = f.load(&temp, attributesFile); err != nil {
		return
	}

	list = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	for _, attrlist := range temp {
		attrlist.MetadataAttribute = irma.MetadataFromInt(attrlist.Ints[0], f.Configuration)
		id := attrlist.CredentialType()
		var ct irma.CredentialTypeIdentifier
		if id != nil {
			ct = id.Identifier()
		}
		if _, contains := list[ct]; !contains {
			list[ct] = []*irma.AttributeList{}
		}
		list[ct] = append(list[ct], attrlist)
	}

	return list, nil
}

func (f *fileStorage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	if err := f.load(&ksses, kssFile); err != nil {
		return nil, err
	}
	return ksses, nil
}

func (f *fileStorage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	if err := f.load(&updates, updatesFile); err != nil {
		return nil, err
	}
	return updates, nil
}

func (f *fileStorage) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	return config, f.load(&config, preferencesFile)
}

func (f *fileStorage) LoadLogs() (logs []*LogEntry, err error) {
	return logs, f.load(&logs, logsFile)
}
