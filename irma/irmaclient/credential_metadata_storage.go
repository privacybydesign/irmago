package irmaclient

import (
	"fmt"

	"github.com/privacybydesign/irmago/irma"
)

type AttributeType string

const (
	AttributeType_Object           AttributeType = "object"
	AttributeType_Array            AttributeType = "array"
	AttributeType_String           AttributeType = "string"
	AttributeType_TranslatedString AttributeType = "translated_string"
	AttributeType_Bool             AttributeType = "boolean"
	AttributeType_Int              AttributeType = "integer"
	AttributeType_Image            AttributeType = "image"
	AttributeType_Base64Image      AttributeType = "base64_image"
)

type AttributeMetadata struct {
	Id     string
	Name   irma.TranslatedString
	Nested []*AttributeMetadata
}

type CredentialMetadata struct {
	CredentialId     string
	Name             irma.TranslatedString
	IssuerId         string
	LogoPath         irma.TranslatedString
	Attributes       []*AttributeMetadata
	CredentialFormat CredentialFormat
	LastUpdated      int
	Source           string
}

type CredentialMetadataStorage interface {
	Store(metadata *CredentialMetadata) error
	GetAll() ([]*CredentialMetadata, error)
	Get(credentialId string) (*CredentialMetadata, error)
	Remove(credentialId string) error
	RemoveAll() error
	RemoveAllFromIssuer(issuerId string) error
}

// ================================================================

type InMemoryCredentialMetadataStorage struct {
	credentials map[string]*CredentialMetadata
}

func NewInMemoryCredentialMetadataStorage() CredentialMetadataStorage {
	return &InMemoryCredentialMetadataStorage{
		credentials: map[string]*CredentialMetadata{},
	}
}

func (s *InMemoryCredentialMetadataStorage) Store(metadata *CredentialMetadata) error {
	s.credentials[metadata.CredentialId] = metadata
	return nil
}

func (s *InMemoryCredentialMetadataStorage) GetAll() ([]*CredentialMetadata, error) {
	result := []*CredentialMetadata{}

	for _, value := range s.credentials {
		result = append(result, value)
	}

	return result, nil
}

func (s *InMemoryCredentialMetadataStorage) Get(credentialId string) (*CredentialMetadata, error) {
	result, ok := s.credentials[credentialId]
	if !ok {
		return nil, fmt.Errorf("failed to get credential metadata for credential with id %v", credentialId)
	}
	return result, nil
}

func (s *InMemoryCredentialMetadataStorage) Remove(credentialId string) error {
	_, ok := s.credentials[credentialId]
	if !ok {
		return fmt.Errorf("tried to delete non-existing credential id '%v'", credentialId)
	}
	delete(s.credentials, credentialId)
	return nil
}

func (s *InMemoryCredentialMetadataStorage) RemoveAll() error {
	s.credentials = map[string]*CredentialMetadata{}
	return nil
}

func (s *InMemoryCredentialMetadataStorage) RemoveAllFromIssuer(issuerId string) error {
	toRemove := []string{}
	for key, value := range s.credentials {
		if value.IssuerId == issuerId {
			toRemove = append(toRemove, key)
		}
	}
	for _, r := range toRemove {
		delete(s.credentials, r)
	}
	return nil
}

// ================================================================

// const credentialMetadataBucket = "credential_metadata"

// type BboldCredentialMetadataStorage struct {
// 	storage *clientstorage.Storage
// }
//
// func NewBboldCredentialMetadataStorage(storage *clientstorage.Storage) *BboldCredentialMetadataStorage {
// 	return &BboldCredentialMetadataStorage{storage: storage}
// }
//
// func (s *BboldCredentialMetadataStorage) Store(metadata *CredentialMetadata) error {
// 	if metadata == nil {
// 		return nil
// 	}
// 	return s.storage.Transaction(func(tx *clientstorage.Transaction) error {
// 		return s.storage.TxStore(tx, credentialMetadataBucket, metadata.CredentialId, metadata)
// 	})
// }
//
// func (s *BboldCredentialMetadataStorage) GetAll() ([]*CredentialMetadata, error) {
// 	var out []*CredentialMetadata
//
// 	err := s.storage.Db.View(func(tx *bbolt.Tx) error {
// 		b := tx.Bucket([]byte(credentialMetadataBucket))
// 		if b == nil {
// 			// No bucket yet => empty result
// 			return nil
// 		}
//
// 		return b.ForEach(func(k, v []byte) error {
// 			plaintext, err := decrypt(v, s.storage.aesKey)
// 			if err != nil {
// 				return err
// 			}
//
// 			var m CredentialMetadata
// 			if err := json.Unmarshal(plaintext, &m); err != nil {
// 				return err
// 			}
//
// 			// take address of a copy
// 			m2 := m
// 			out = append(out, &m2)
// 			return nil
// 		})
// 	})
//
// 	return out, err
// }
//
// func (s *BboldCredentialMetadataStorage) Get(credentialId string) (*CredentialMetadata, error) {
// 	var m CredentialMetadata
// 	found, err := s.storage.Load(credentialMetadataBucket, credentialId, &m)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if !found {
// 		return nil, nil
// 	}
// 	return &m, nil
// }
//
// func (s *BboldCredentialMetadataStorage) Remove(credentialId string) error {
// 	return s.storage.Transaction(func(tx *Transaction) error {
// 		return s.storage.TxDelete(tx, credentialMetadataBucket, credentialId)
// 	})
// }
//
// func (s *BboldCredentialMetadataStorage) RemoveAll() error {
// 	return s.storage.Transaction(func(tx *Transaction) error {
// 		// Delete the whole bucket (like a purge of this data set).
// 		err := tx.DeleteBucket([]byte(credentialMetadataBucket))
// 		if err == bbolt.ErrBucketNotFound {
// 			return nil
// 		}
// 		return err
// 	})
// }
//
// func (s *BboldCredentialMetadataStorage) RemoveAllFromIssuer(issuerId string) error {
// 	if issuerId == "" {
// 		return nil
// 	}
//
// 	return s.storage.Transaction(func(tx *Transaction) error {
// 		b := tx.Bucket([]byte(credentialMetadataBucket))
// 		if b == nil {
// 			return nil
// 		}
//
// 		// Collect keys to delete (don’t delete while iterating with ForEach).
// 		var keysToDelete [][]byte
//
// 		err := b.ForEach(func(k, v []byte) error {
// 			plaintext, err := decrypt(v, s.storage.aesKey)
// 			if err != nil {
// 				return err
// 			}
//
// 			// Only need IssuerId (and maybe CredentialId), but simplest is full unmarshal.
// 			var m CredentialMetadata
// 			if err := json.Unmarshal(plaintext, &m); err != nil {
// 				return err
// 			}
//
// 			if m.IssuerId == issuerId {
// 				kk := make([]byte, len(k))
// 				copy(kk, k)
// 				keysToDelete = append(keysToDelete, kk)
// 			}
// 			return nil
// 		})
// 		if err != nil {
// 			return err
// 		}
//
// 		for _, k := range keysToDelete {
// 			if err := b.Delete(k); err != nil {
// 				return err
// 			}
// 		}
// 		return nil
// 	})
// }
