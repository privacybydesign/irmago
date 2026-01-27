package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/internal/clientstorage"
	"github.com/privacybydesign/irmago/irma"
	"go.etcd.io/bbolt"
)

// ========================================================================

// SdJwtVcBatchInstanceData corresponds to a batch of SdJwtVcs that are the same in everything
// except for the keybinding pub keys and disclosure salts/hashes
type SdJwtVcBatchInstanceData struct {
	BatchSize              uint           // number of instances originally issued
	RemainingInstanceCount uint           // number of instances left
	SignedOn               irma.Timestamp // Unix timestamp
	Expires                irma.Timestamp // Unix timestamp
	Attributes             map[string]any // Human-readable rendered attributes
	Hash                   string         // SHA256 hash over the attributes and credential type
	CredentialType         string         // corresponds to 'vct' field in jwt
}

// SdJwtVcInstanceData corresponds to a single instance of and SdJwtVc
type SdJwtVcInstanceData struct {
	SignedOn       irma.Timestamp // Unix timestamp
	Expires        irma.Timestamp // Unix timestamp
	Attributes     map[string]any // Human-readable rendered attributes
	Hash           string         // SHA256 hash over the attributes and credential type
	CredentialType string         // corresponds to 'vct' field in jwt
}

type SdJwtVcStorage interface {
	// RemoveAll should remove all instances for the credential with the given hash.
	RemoveAll() error
	// RemoveCredentialByHash should remove all instances for the credential with the given hash.
	// Returns a list of jwk holder pub keys that can be used to delete corresponding private keys
	// Should _not_ return an error if the credential is not found, only when there's storage issues.
	RemoveCredentialByHash(hash string) ([]jwk.Key, error)

	// RemoveLastUsedInstanceOfCredentialByHash should remove a single instance
	// (the last used one) of the credential for the given hash.
	RemoveLastUsedInstanceOfCredentialByHash(hash string) error

	// StoreCredential assumes each of the provided sdjwts to be linked to the credential info
	StoreCredential(info SdJwtVcBatchInstanceData, credentials []sdjwtvc.SdJwtVc) error

	// GetCredentialsForId gets all instances for a credential id from the scheme
	GetCredentialsForId(id string) []SdJwtVcAndInfo
	GetCredentialByHash(hash string) (*SdJwtVcAndInfo, error)
	GetCredentialMetdataList() []SdJwtVcBatchInstanceData
}

type SdJwtVcAndInfo struct {
	SdJwtVc  sdjwtvc.SdJwtVc
	Metadata SdJwtVcBatchInstanceData
}

// ========================================================================

const (
	sdjwtvcBucketName = "dc+sd-jwt"
	infoKey           = "info"
	credentialsKey    = "credentials"
)

func NewBboltSdJwtVcStorage(s *clientstorage.Storage) *BboltSdJwtVcStorage {
	return &BboltSdJwtVcStorage{storage: s}
}

type BboltSdJwtVcStorage struct {
	// Layout for the sdjwtvc bucket in this database:
	// - dc+sd-jwt: bucket
	// ----- hash: bucket
	// --------- info: encrypted-serialized CredentialInfo
	// --------- credentials: bucket
	// ------------- id: encrypted sdjwtvc string
	// ------------- id: encrypted sdjwtvc string
	// ------------- id: encrypted sdjwtvc string
	// ----- hash: bucket
	// --------- info: encrypted-serialized CredentialInfo
	// --------- credentials: bucket
	// ------------- id: encrypted sdjwtvc string
	// ------------- id: encrypted sdjwtvc string
	// ------------- id: encrypted sdjwtvc string
	storage *clientstorage.Storage
}

func (s *BboltSdJwtVcStorage) RemoveAll() (err error) {
	err = s.storage.Db.Update(func(tx *bbolt.Tx) error {
		// if bucket doesn't exist, abort
		if tx.Bucket([]byte(sdjwtvcBucketName)) == nil {
			return nil
		}
		err := tx.DeleteBucket([]byte(sdjwtvcBucketName))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *BboltSdJwtVcStorage) RemoveCredentialByHash(hash string) (holderKeys []jwk.Key, err error) {
	err = s.storage.Db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))
		// if the sdjwtvc bucket doesn't exist, the credential to remove obviously also doesn't...
		if sdjwtBucket == nil {
			return nil
		}

		credentialBucket := sdjwtBucket.Bucket([]byte(hash))
		if credentialBucket == nil {
			return nil
		}

		instancesBucket := credentialBucket.Bucket([]byte(credentialsKey))
		if instancesBucket == nil {
			return fmt.Errorf("credential bucket exists but sdjwtvc instances are not there")
		}

		err := instancesBucket.ForEach(func(key, value []byte) error {
			sdjwtBytes, err := s.storage.Decrypt(value)
			if err != nil {
				return fmt.Errorf("failed to decrypt sdjwt while extracting holder key: %v", err)
			}
			sdjwt := sdjwtvc.SdJwtVc(sdjwtBytes)
			_, holderKey, err := sdjwtvc.ExtractHashingAlgorithmAndHolderPubKey(sdjwt)
			if err != nil {
				return err
			}
			holderKeys = append(holderKeys, holderKey)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to extract holder keys: %v", err)
		}

		err = sdjwtBucket.DeleteBucket([]byte(hash))

		if err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		return nil
	})
	return holderKeys, err
}

func (s *BboltSdJwtVcStorage) RemoveLastUsedInstanceOfCredentialByHash(hash string) error {
	err := s.storage.Db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))
		// if the sdjwtvc bucket doesn't exist, the credential to remove obviously also doesn't...
		if sdjwtBucket == nil {
			return fmt.Errorf("tried to remove sdjwt instance while there's no sdjwt bucket yet")
		}

		credBucket := sdjwtBucket.Bucket([]byte(hash))
		// if the credential bucket doesn't exist, the credential to remove obviously also doesn't...
		if credBucket == nil {
			return fmt.Errorf("no credential bucket found for %s", string(hash))
		}

		credentialsBucket := credBucket.Bucket([]byte(credentialsKey))
		if credentialsBucket == nil {
			return fmt.Errorf("no credential instances found for %s", string(hash))
		}

		key, _ := credentialsBucket.Cursor().First()
		err := credentialsBucket.Delete(key)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func (s *BboltSdJwtVcStorage) StoreCredential(info SdJwtVcBatchInstanceData, credentials []sdjwtvc.SdJwtVc) error {
	return s.storage.Db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket, err := tx.CreateBucketIfNotExists([]byte(sdjwtvcBucketName))

		if err != nil {
			return err
		}

		credBucket, err := sdjwtBucket.CreateBucketIfNotExists([]byte(info.Hash))
		if err != nil {
			return err
		}

		// if the info is not there yet...
		if credBucket.Get([]byte(infoKey)) == nil {
			// put the info there...
			marshalled, err := json.Marshal(info)
			if err != nil {
				return err
			}

			encryptedInfo, err := s.storage.Encrypt(marshalled)
			if err != nil {
				return err
			}
			credBucket.Put([]byte(infoKey), encryptedInfo)
		}

		if credBucket.Bucket([]byte(credentialsKey)) != nil {
			if err = credBucket.DeleteBucket([]byte(credentialsKey)); err != nil {
				return fmt.Errorf("failed to delete bucket: %v", err)
			}
		}

		rawCredentialsBucket, err := credBucket.CreateBucketIfNotExists([]byte(credentialsKey))
		if err != nil {
			return err
		}

		for _, sdjwt := range credentials {
			id, err := credBucket.NextSequence()
			if err != nil {
				return err
			}
			encryptedSdjwt, err := s.storage.Encrypt([]byte(sdjwt))
			if err != nil {
				return err
			}
			err = rawCredentialsBucket.Put(itob(id), encryptedSdjwt)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *BboltSdJwtVcStorage) GetCredentialsForId(id string) (result []SdJwtVcAndInfo) {
	err := s.storage.Db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return fmt.Errorf("sdjwtvc bucket doesn't exist")
		}

		return sdjwtBucket.ForEach(func(key []byte, value []byte) error {
			if value == nil {
				bucket := sdjwtBucket.Bucket(key)
				info, err := s.getCredentialInfoFromBucket(bucket)
				if err != nil {
					return fmt.Errorf("failed to get credential info from bucket: %v", err)
				}
				if info.CredentialType == id {
					sdjwt, _ := s.getFirstCredentialInstanceFromBucket(bucket)
					result = append(result, SdJwtVcAndInfo{
						SdJwtVc:  sdjwt,
						Metadata: *info,
					})
				}
			}
			return nil
		})
	})
	if err != nil {
		irma.Logger.Errorf("bbolt GetCredentialsForId: %v", err)
	}
	return result
}

func getCredentialInstanceCount(bucket *bbolt.Bucket) (uint, error) {
	creds := bucket.Bucket([]byte(credentialsKey))
	if creds == nil {
		return 0, fmt.Errorf("no credentials bucket found")
	}
	return uint(creds.Stats().KeyN), nil
}

func (s *BboltSdJwtVcStorage) GetCredentialByHash(hash string) (result *SdJwtVcAndInfo, err error) {
	err = s.storage.Db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return fmt.Errorf("sdjwtvc bucket doesn't exist")
		}

		credentialBucket := sdjwtBucket.Bucket([]byte(hash))
		if credentialBucket == nil {
			return fmt.Errorf("failed to find credential for hash: %s", hash)
		}

		result, err = s.getCredential(credentialBucket)
		return err
	})

	return result, err
}

func (s *BboltSdJwtVcStorage) GetCredentialMetdataList() []SdJwtVcBatchInstanceData {
	result := []SdJwtVcBatchInstanceData{}
	s.storage.Db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return nil
		}

		return sdjwtBucket.ForEach(func(key []byte, value []byte) error {
			bucket := sdjwtBucket.Bucket(key)
			info, err := s.getCredentialInfoFromBucket(bucket)

			if err != nil {
				return err
			}

			result = append(result, *info)
			return nil
		})
	})

	return result
}

func (s *BboltSdJwtVcStorage) getCredential(credentialBucket *bbolt.Bucket) (*SdJwtVcAndInfo, error) {
	info, err := s.getCredentialInfoFromBucket(credentialBucket)
	if err != nil {
		return nil, err
	}
	sdjwt, err := s.getFirstCredentialInstanceFromBucket(credentialBucket)
	if err != nil {
		return nil, err
	}

	return &SdJwtVcAndInfo{
		Metadata: *info,
		SdJwtVc:  sdjwt,
	}, nil
}

// itob returns an 8-byte big endian representation of v.
func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func (s *BboltSdJwtVcStorage) getFirstCredentialInstanceFromBucket(bucket *bbolt.Bucket) (sdjwtvc.SdJwtVc, error) {
	creds := bucket.Bucket([]byte(credentialsKey))
	if creds == nil {
		return "", fmt.Errorf("no credentials bucket found")
	}
	_, value := creds.Cursor().First()
	if value == nil {
		return "", fmt.Errorf("no sdjwtvc instance left for this credential")
	}
	decrypted, err := s.storage.Decrypt(value)
	if err != nil {
		return "", err
	}
	return sdjwtvc.SdJwtVc(decrypted), nil
}

func (s *BboltSdJwtVcStorage) getCredentialInfoFromBucket(bucket *bbolt.Bucket) (*SdJwtVcBatchInstanceData, error) {
	encrypted := bucket.Get([]byte(infoKey))
	decrypted, err := s.storage.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	var info SdJwtVcBatchInstanceData
	err = json.Unmarshal(decrypted, &info)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v (%v)", err, string(decrypted))
	}

	instanceCount, err := getCredentialInstanceCount(bucket)

	if err != nil {
		return nil, fmt.Errorf("failed to get instance count: %v", err)
	}

	info.RemainingInstanceCount = instanceCount
	return &info, nil
}

// ==================================================================================

type sdjwtvcStorageEntry struct {
	// A list of strings containing sdjwtvc's (with all disclosures & without kbjwt)
	rawCredentials []sdjwtvc.SdJwtVc
	info           SdJwtVcBatchInstanceData
}

type InMemorySdJwtVcStorage struct {
	entries []sdjwtvcStorageEntry
}

func (s *InMemorySdJwtVcStorage) GetCredentialByHash(hash string) (*SdJwtVcAndInfo, error) {
	for _, entry := range s.entries {
		if entry.info.Hash == hash {
			return &SdJwtVcAndInfo{
				Metadata: entry.info,
				SdJwtVc:  entry.rawCredentials[0],
			}, nil
		}
	}
	return nil, fmt.Errorf("no entry found for hash '%s'", hash)
}

func NewInMemorySdJwtVcStorage() (*InMemorySdJwtVcStorage, error) {
	storage := &InMemorySdJwtVcStorage{
		entries: []sdjwtvcStorageEntry{},
	}
	return storage, nil
}

func (s *InMemorySdJwtVcStorage) RemoveAll() error {
	return nil
}

func (s *InMemorySdJwtVcStorage) RemoveLastUsedInstanceOfCredentialByHash(id string) error {
	return nil
}

func (s *InMemorySdJwtVcStorage) RemoveCredentialByHash(hash string) ([]jwk.Key, error) {
	return nil, nil
}

func (s *InMemorySdJwtVcStorage) GetCredentialMetdataList() []SdJwtVcBatchInstanceData {
	result := []SdJwtVcBatchInstanceData{}

	for _, entry := range s.entries {
		result = append(result, entry.info)
	}

	return result
}

func (s *InMemorySdJwtVcStorage) GetCredentialsForId(id string) []SdJwtVcAndInfo {
	result := []SdJwtVcAndInfo{}
	for _, entry := range s.entries {
		// we have an instance of the requested credential type
		if id == entry.info.CredentialType {
			result = append(result, SdJwtVcAndInfo{
				Metadata: entry.info,
				SdJwtVc:  entry.rawCredentials[0],
			})
		}
	}
	return result
}

func (s *InMemorySdJwtVcStorage) StoreCredential(info SdJwtVcBatchInstanceData, credentials []sdjwtvc.SdJwtVc) error {
	s.entries = append(s.entries, sdjwtvcStorageEntry{
		info:           info,
		rawCredentials: credentials,
	})
	return nil
}
