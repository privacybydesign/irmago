package keyshareserver

import (
	"encoding/binary"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server/keyshare"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/server"
)

type DBType string

var errUnknownDBType = errors.New("Unknown database type")

const (
	DBTypeMemory   DBType = "memory"
	DBTypePostgres DBType = "postgres"
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// IRMA server configuration
	*server.Configuration `mapstructure:",squash"`

	// Database configuration (ignored when database is provided)
	DBType            DBType `json:"db_type" mapstructure:"db_type"`
	DBConnStr         string `json:"db_str" mapstructure:"db_str"`
	DBConnMaxIdle     int    `json:"db_max_idle" mapstructure:"db_max_idle"`
	DBConnMaxOpen     int    `json:"db_max_open" mapstructure:"db_max_open"`
	DBConnMaxIdleTime int    `json:"db_max_idle_time" mapstructure:"db_max_idle_time"`
	DBConnMaxOpenTime int    `json:"db_max_open_time" mapstructure:"db_max_open_time"`
	// Provide a prepared database (useful for testing)
	DB DB `json:"-"`

	// Configuration of secure Core
	// Private key used to sign JWTs with
	JwtKeyID          uint32 `json:"jwt_key_id" mapstructure:"jwt_key_id"`
	JwtIssuer         string `json:"jwt_issuer" mapstructure:"jwt_issuer"`
	JwtPinExpiry      int    `json:"jwt_pin_expiry" mapstructure:"jwt_pin_expiry"`
	JwtPrivateKey     string `json:"jwt_privkey" mapstructure:"jwt_privkey"`
	JwtPrivateKeyFile string `json:"jwt_privkey_file" mapstructure:"jwt_privkey_file"`
	// Decryption keys used for user secrets
	StorageFallbackKeysDir string `json:"storage_fallback_keys_dir" mapstructure:"storage_fallback_keys_dir"`
	StoragePrimaryKeyFile  string `json:"storage_primary_key_file" mapstructure:"storage_primary_key_file"`

	// Keyshare attribute to issue during registration
	KeyshareAttribute irma.AttributeTypeIdentifier `json:"keyshare_attribute" mapstructure:"keyshare_attribute"`

	// Configuration for email sending during registration (email address use will be disabled if not present)
	keyshare.EmailConfiguration `mapstructure:",squash"`

	RegistrationEmailFiles     map[string]string `json:"registration_email_files" mapstructure:"registration_email_files"`
	RegistrationEmailSubjects  map[string]string `json:"registration_email_subjects" mapstructure:"registration_email_subjects"`
	registrationEmailTemplates map[string]*template.Template

	VerificationURL map[string]string `json:"verification_url" mapstructure:"verification_url"`
	// Amount of time user's email validation token is valid (in hours)
	EmailTokenValidity int `json:"email_token_validity" mapstructure:"email_token_validity"`
}

func readAESKey(filename string) (uint32, keysharecore.AESKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return 0, keysharecore.AESKey{}, err
	}
	if len(keyData) != 32+4 {
		return 0, keysharecore.AESKey{}, errors.New("Invalid aes key")
	}
	var key [32]byte
	copy(key[:], keyData[4:36])
	return binary.LittleEndian.Uint32(keyData[0:4]), key, nil
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func validateConf(conf *Configuration) error {
	// Setup email templates
	var err error
	if conf.EmailServer != "" {
		conf.registrationEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.RegistrationEmailFiles,
			conf.RegistrationEmailSubjects,
			conf.DefaultLanguage,
		)
		if err != nil {
			return server.LogError(err)
		}
		if _, ok := conf.VerificationURL[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing verification base url for default language"))
		}
	}

	if err = conf.VerifyEmailServer(); err != nil {
		return server.LogError(err)
	}

	if conf.IrmaConfiguration.AttributeTypes[conf.KeyshareAttribute] == nil {
		return server.LogError(errors.Errorf("Unknown keyshare attribute: %s", conf.KeyshareAttribute))
	}
	_, err = conf.IrmaConfiguration.PrivateKeys.Latest(conf.KeyshareAttribute.CredentialTypeIdentifier().IssuerIdentifier())
	if err != nil {
		return server.LogError(errors.Errorf("Failed to load private key of keyshare attribute: %v", err))
	}

	// Setup IRMA session server url for in QR code
	if !strings.HasSuffix(conf.URL, "/") {
		conf.URL += "/"
	}
	conf.URL += "irma/"

	if conf.EmailTokenValidity == 0 {
		conf.EmailTokenValidity = 168 // set default of 7 days
	}
	if conf.EmailTokenValidity < 1 || conf.EmailTokenValidity > 8760 {
		return server.LogError(errors.Errorf("EmailTokenValidity (%d) is less than one hour or more than one year", conf.EmailTokenValidity))
	}
	return nil
}

func setupDatabase(conf *Configuration) (DB, error) {
	var db DB
	switch conf.DBType {
	case DBTypeMemory:
		db = NewMemoryDB()
	case DBTypePostgres:
		var err error
		db, err = newPostgresDB(conf.DBConnStr,
			conf.DBConnMaxIdle,
			conf.DBConnMaxOpen,
			time.Duration(conf.DBConnMaxIdleTime)*time.Second,
			time.Duration(conf.DBConnMaxOpenTime)*time.Second,
		)
		if err != nil {
			return nil, server.LogError(err)
		}
	default:
		return nil, server.LogError(errUnknownDBType)
	}
	return db, nil
}

func setupCore(conf *Configuration) (*keysharecore.Core, error) {
	// Parse keysharecore private keys and create a valid keyshare core
	if conf.JwtPrivateKey == "" && conf.JwtPrivateKeyFile == "" {
		return nil, server.LogError(errors.Errorf("Missing keyshare server jwt key"))
	}
	keybytes, err := common.ReadKey(conf.JwtPrivateKey, conf.JwtPrivateKeyFile)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to read keyshare server jwt key", 0))
	}
	jwtPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keybytes)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to read keyshare server jwt key", 0))
	}
	storagePrimaryKeyFilePath, err := filepath.Abs(conf.StoragePrimaryKeyFile)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to get absolute path of primary storage key", 0))
	}
	decKeyID, decKey, err := readAESKey(storagePrimaryKeyFilePath)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to load primary storage key", 0))
	}

	core := keysharecore.NewKeyshareCore(&keysharecore.Configuration{
		DecryptionKeyID: decKeyID,
		DecryptionKey:   decKey,
		JWTPrivateKeyID: conf.JwtKeyID,
		JWTPrivateKey:   jwtPrivateKey,
		JWTIssuer:       conf.JwtIssuer,
		JWTPinExpiry:    conf.JwtPinExpiry,
	})
	if conf.StorageFallbackKeysDir != "" {
		dirEntries, err := os.ReadDir(conf.StorageFallbackKeysDir)
		if err != nil {
			return nil, server.LogError(errors.WrapPrefix(err, "failed to read fallback keys directory", 0))
		}
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() || !strings.HasSuffix(dirEntry.Name(), ".key") || strings.HasPrefix(dirEntry.Name(), ".") {
				conf.Logger.Warnf("Ignoring storage fallback key file %s", dirEntry.Name())
				continue
			}

			pth, err := filepath.Abs(path.Join(conf.StorageFallbackKeysDir, dirEntry.Name()))
			if err != nil {
				return nil, server.LogError(errors.WrapPrefix(err, "failed to get absolute path of fallback key "+dirEntry.Name(), 0))
			}
			if pth == storagePrimaryKeyFilePath {
				conf.Logger.Debugf("Skipping primary storage key %s as fallback key", dirEntry.Name())
				continue
			}

			id, key, err := readAESKey(pth)
			if err != nil {
				return nil, server.LogError(errors.WrapPrefix(err, "failed to load fallback key "+dirEntry.Name(), 0))
			}
			core.DangerousAddDecryptionKey(id, key)
		}
	}

	return core, nil
}
