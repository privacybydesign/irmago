package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/testdata"
	"go.etcd.io/bbolt"
)

// ========================================================================

type SdJwtVcStorage interface {
	// RemoveAll should remove all instances for the credential with the given hash.
	RemoveAll() error
	// RemoveCredentialByHash should remove all instances for the credential with the given hash.
	// Should _not_ return an error if the credential is not found.
	RemoveCredentialByHash(hash string) error

	// RemoveLastUsedInstanceOfCredentialByHash should remove a single instance
	// (the last used one) of the credential for the given hash.
	RemoveLastUsedInstanceOfCredentialByHash(hash string) error

	// StoreCredential assumes each of the provided sdjwts to be linked to the credential info
	StoreCredential(info irma.CredentialInfo, credentials []sdjwtvc.SdJwtVc) error

	// GetCredentialsForId gets all instances for a credential id from the scheme
	GetCredentialsForId(id string) []SdJwtVcAndInfo
	GetCredentialByHash(hash string) (*SdJwtVcAndInfo, error)
	GetCredentialInfoList() irma.CredentialInfoList
}

type SdJwtVcAndInfo struct {
	SdJwtVc sdjwtvc.SdJwtVc
	Info    irma.CredentialInfo
}

// ========================================================================

const (
	sdjwtvcBucketName = "dc+sd-jwt"
	infoKey           = "info"
	credentialsKey    = "credentials"
)

func NewBBoltSdJwtVcStorage(db *bbolt.DB, aesKey [32]byte) *BboltSdJwtVcStorage {
	return &BboltSdJwtVcStorage{db: db, aesKey: aesKey}
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
	db     *bbolt.DB
	aesKey [32]byte
}

func (s *BboltSdJwtVcStorage) RemoveAll() (err error) {
	err = s.db.Update(func(tx *bbolt.Tx) error {
		err := tx.DeleteBucket([]byte(sdjwtvcBucketName))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *BboltSdJwtVcStorage) RemoveCredentialByHash(hash string) (err error) {
	err = s.db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))
		// if the sdjwtvc bucket doesn't exist, the credential to remove obviously also doesn't...
		if sdjwtBucket == nil {
			return nil
		}

		err := sdjwtBucket.DeleteBucket([]byte(hash))

		if err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		return nil
	})
	return err
}

func (s *BboltSdJwtVcStorage) RemoveLastUsedInstanceOfCredentialByHash(hash string) (err error) {
	err = s.db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))
		// if the sdjwtvc bucket doesn't exist, the credential to remove obviously also doesn't...
		if sdjwtBucket == nil {
			return nil
		}

		credBucket := tx.Bucket([]byte(hash))
		// if the credential bucket doesn't exist, the credential to remove obviously also doesn't...
		if credBucket == nil {
			return nil
		}

		credentialsBucket := tx.Bucket([]byte(credentialsKey))
		if credentialsBucket == nil {
			return nil
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

func (s *BboltSdJwtVcStorage) StoreCredentials(info irma.CredentialInfo, credentials []sdjwtvc.SdJwtVc) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		sdjwtBucket, err := tx.CreateBucketIfNotExists([]byte(sdjwtvcBucketName))

		if err != nil {
			return err
		}

		credBucket, err := sdjwtBucket.CreateBucketIfNotExists([]byte(info.Hash))
		if err != nil {
			return err
		}

		encryptedInfo, err := marshalAndEncryptInfo(info, s.aesKey)
		if err != nil {
			return err
		}
		credBucket.Put([]byte(infoKey), encryptedInfo)

		rawCredentialsBucket, err := credBucket.CreateBucket([]byte(credentialsKey))
		if err != nil {
			return err
		}

		for _, sdjwt := range credentials {
			id, err := credBucket.NextSequence()
			if err != nil {
				return err
			}
			encryptedSdjwt, err := encrypt([]byte(sdjwt), s.aesKey)
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
	err := s.db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return fmt.Errorf("sdjwtvc bucket doesn't exist")
		}

		return sdjwtBucket.ForEach(func(key []byte, value []byte) error {
			if value == nil {
				bucket := sdjwtBucket.Bucket(key)
				info, err := getCredentialInfoFromBucket(bucket, s.aesKey)
				if err != nil {
					return fmt.Errorf("failed to get credential info from bucket: %v", err)
				}
				infoId := fmt.Sprintf("%s.%s.%s", info.SchemeManagerID, info.IssuerID, info.ID)
				if infoId == id {
					sdjwt, err := getFirstCredentialInstanceFromBucket(bucket, s.aesKey)
					if err != nil {
						return err
					}
					result = append(result, SdJwtVcAndInfo{
						SdJwtVc: sdjwt,
						Info:    *info,
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

func (s *BboltSdJwtVcStorage) GetCredentialByHash(hash string) (result *SdJwtVcAndInfo, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return fmt.Errorf("sdjwtvc bucket doesn't exist")
		}

		credentialBucket := sdjwtBucket.Bucket([]byte(hash))
		if credentialBucket == nil {
			return fmt.Errorf("failed to find credential for hash: %s", hash)
		}

		result, err = getCredential(credentialBucket, s.aesKey)
		return err
	})

	return result, err
}

func (s *BboltSdJwtVcStorage) GetCredentialInfoList() (result irma.CredentialInfoList) {
	s.db.View(func(tx *bbolt.Tx) error {
		sdjwtBucket := tx.Bucket([]byte(sdjwtvcBucketName))

		if sdjwtBucket == nil {
			return nil
		}

		err := sdjwtBucket.Tx().ForEach(func(key []byte, bucket *bbolt.Bucket) error {
			info, err := getCredentialInfoFromBucket(bucket, s.aesKey)

			if err != nil {
				return err
			}

			result = append(result, info)
			return nil
		})
		return err
	})

	return result
}

func getCredential(credentialBucket *bbolt.Bucket, aesKey [32]byte) (*SdJwtVcAndInfo, error) {
	info, err := getCredentialInfoFromBucket(credentialBucket, aesKey)
	if err != nil {
		return nil, err
	}
	sdjwt, err := getFirstCredentialInstanceFromBucket(credentialBucket, aesKey)
	if err != nil {
		return nil, err
	}

	return &SdJwtVcAndInfo{
		Info:    *info,
		SdJwtVc: sdjwt,
	}, nil
}

// itob returns an 8-byte big endian representation of v.
func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func marshalAndEncryptInfo(info irma.CredentialInfo, aesKey [32]byte) ([]byte, error) {
	marshalled, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}

	return encrypt(marshalled, aesKey)
}

func getFirstCredentialInstanceFromBucket(bucket *bbolt.Bucket, aesKey [32]byte) (sdjwtvc.SdJwtVc, error) {
	creds := bucket.Bucket([]byte(credentialsKey))
	if creds == nil {
		return "", fmt.Errorf("no credentials bucket found")
	}
	_, value := creds.Cursor().First()
	if value == nil {
		return "", fmt.Errorf("no sdjwtvc instance left for this credential")
	}
	decrypted, err := decrypt(value, aesKey)
	if err != nil {
		return "", err
	}
	return sdjwtvc.SdJwtVc(decrypted), nil
}

func getCredentialInfoFromBucket(bucket *bbolt.Bucket, aesKey [32]byte) (*irma.CredentialInfo, error) {
	encrypted := bucket.Get([]byte(infoKey))
	decrypted, err := decrypt(encrypted, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	var info irma.CredentialInfo
	err = json.Unmarshal(decrypted, &info)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v (%v)", err, string(decrypted))
	}

	return &info, nil
}

// ==================================================================================

type sdjwtvcStorageEntry struct {
	// A list of strings containing sdjwtvc's (with all disclosures & without kbjwt)
	rawRedentials []sdjwtvc.SdJwtVc
	info          irma.CredentialInfo
}

type InMemorySdJwtVcStorage struct {
	entries []sdjwtvcStorageEntry
}

func (s *InMemorySdJwtVcStorage) GetCredentialByHash(hash string) (*SdJwtVcAndInfo, error) {
	for _, entry := range s.entries {
		if entry.info.Hash == hash {
			return &SdJwtVcAndInfo{
				Info:    entry.info,
				SdJwtVc: entry.rawRedentials[0],
			}, nil
		}
	}
	return nil, fmt.Errorf("no entry found for hash '%s'", hash)
}

func createSdJwtVc(vct, issuerUrl string, claims map[string]any) (sdjwtvc.SdJwtVc, error) {
	contents, err := sdjwtvc.MultipleNewDisclosureContents(claims)
	if err != nil {
		return "", err
	}

	signer := sdjwtvc.NewEcdsaJwtCreatorWithIssuerTestkey()
	return sdjwtvc.NewSdJwtVcBuilder().
		WithDisclosures(contents).
		WithHolderKey(testdata.ParseHolderPubJwk()).
		WithHashingAlgorithm(sdjwtvc.HashAlg_Sha256).
		WithVerifiableCredentialType(vct).
		WithIssuerUrl(issuerUrl).
		WithClock(sdjwtvc.NewSystemClock()).
		WithLifetime(1000000000).
		Build(signer)
}

func NewInMemorySdJwtVcStorage() (*InMemorySdJwtVcStorage, error) {
	storage := &InMemorySdJwtVcStorage{
		entries: []sdjwtvcStorageEntry{},
	}

	// ignoring all errors here, since it's not production code anyway
	mobilephoneEntry, _ := createSdJwtVc("pbdf.pbdf.mobilenumber", "https://openid4vc.staging.yivi.app",
		map[string]any{
			"mobilenumber": "+31612345678",
		},
	)

	info, _ := createCredentialInfoFromSdJwtVc(mobilephoneEntry)
	storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{mobilephoneEntry})

	emailEntry, _ := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})

	info, _ = createCredentialInfoFromSdJwtVc(emailEntry)
	storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{emailEntry})

	emailEntry2, _ := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	})

	emailEntry3, _ := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	})

	info, _ = createCredentialInfoFromSdJwtVc(emailEntry2)
	storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{emailEntry2, emailEntry3})
	return storage, nil
}

func (s *InMemorySdJwtVcStorage) RemoveAll() error {
	return nil
}

func (s *InMemorySdJwtVcStorage) RemoveLastUsedInstanceOfCredentialByHash(id string) error {
	return nil
}

func (s *InMemorySdJwtVcStorage) RemoveCredentialByHash(hash string) error {

	return nil
}

func (s *InMemorySdJwtVcStorage) GetCredentialInfoList() irma.CredentialInfoList {
	result := irma.CredentialInfoList{}

	for _, entry := range s.entries {
		result = append(result, &entry.info)
	}

	return result
}

func (s *InMemorySdJwtVcStorage) GetCredentialsForId(id string) []SdJwtVcAndInfo {
	result := []SdJwtVcAndInfo{}
	for _, entry := range s.entries {
		credId := fmt.Sprintf("%s.%s.%s", entry.info.SchemeManagerID, entry.info.IssuerID, entry.info.ID)

		// we have an instance of the requested credential type
		if id == credId {
			result = append(result, SdJwtVcAndInfo{
				Info:    entry.info,
				SdJwtVc: entry.rawRedentials[0],
			})
		}
	}
	return result
}

func (s *InMemorySdJwtVcStorage) StoreCredential(info irma.CredentialInfo, credentials []sdjwtvc.SdJwtVc) error {
	s.entries = append(s.entries, sdjwtvcStorageEntry{
		info:          info,
		rawRedentials: credentials,
	})
	return nil
}

func createCredentialInfoFromSdJwtVc(cred sdjwtvc.SdJwtVc) (*irma.CredentialInfo, error) {
	ctx := sdjwtvc.VerificationContext{
		IssuerMetadataFetcher: sdjwtvc.NewHttpIssuerMetadataFetcher(),
		Clock:                 sdjwtvc.NewSystemClock(),
		JwtVerifier:           sdjwtvc.NewJwxJwtVerifier(),
	}
	decoded, err := sdjwtvc.ParseAndVerifySdJwtVc(ctx, cred)

	if err != nil {
		return nil, err
	}

	attributes := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for _, d := range decoded.Disclosures {
		strValue, ok := d.Value.(string)
		if !ok {
			return nil, fmt.Errorf("failed to convert disclosure to string for attribute '%s'", d.Key)
		}
		schemeId := fmt.Sprintf("%s.%s", decoded.IssuerSignedJwtPayload.VerifiableCredentialType, d.Key)
		id := irma.NewAttributeTypeIdentifier(schemeId)
		attributes[id] = irma.TranslatedString{
			"":   strValue,
			"en": strValue,
			"nl": strValue,
		}
	}

	hashContent, err := json.Marshal(attributes)
	if err != nil {
		return nil, err
	}

	hash, err := sdjwtvc.CreateHash(sdjwtvc.HashAlg_Sha256, string(hashContent))
	if err != nil {
		return nil, err
	}

	idComponents := strings.Split(decoded.IssuerSignedJwtPayload.VerifiableCredentialType, ".")
	if num := len(idComponents); num != 3 {
		return nil, fmt.Errorf(
			"credential id expected to have exactly 3 components, separated by dots: %s",
			decoded.IssuerSignedJwtPayload.VerifiableCredentialType,
		)
	}
	info := irma.CredentialInfo{
		ID:              idComponents[2],
		IssuerID:        idComponents[1],
		SchemeManagerID: idComponents[0],
		SignedOn: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(decoded.IssuerSignedJwtPayload.Expiry, 0),
		),
		Attributes:          attributes,
		Hash:                hash,
		Revoked:             false,
		RevocationSupported: false,
		CredentialFormat:    "dc+sd-jwt",
	}
	return &info, nil
}
