package keyshareserver

import (
	"encoding/binary"
	"html/template"
	"io/ioutil"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server/keyshare"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server"
)

type DatabaseType string

var ErrUnknownDatabaseType = errors.New("Unknown database type")

const (
	DatabaseTypeMemory   = "memory"
	DatabaseTypePostgres = "postgres"
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// IRMA server configuration
	*server.Configuration `mapstructure:",squash"`

	// Database configuration (ignored when database is provided)
	DBType       DatabaseType `json:"db_type" mapstructure:"db_type"`
	DBConnstring string       `json:"db_connstring" mapstructure:"db_connstring"`
	// Provide a prepared database (useful for testing)
	DB KeyshareDB `json:"-"`

	PathPrefix string `json:"path_prefix" mapstructure:"path_prefix"`

	// Configuration of secure Core
	// Private key used to sign JWTs with
	JwtKeyID          uint32 `json:"jwt_key_id" mapstructure:"jwt_key_id"`
	JwtPrivateKey     string `json:"jwt_privkey" mapstructure:"jwt_privkey"`
	JwtPrivateKeyFile string `json:"jwt_privkey_file" mapstructure:"jwt_privkey_file"`
	// Decryption keys used for keyshare packets
	StorageFallbackKeyFiles []string `json:"storage_fallback_key_files" mapstructure:"storage_fallback_key_files"`
	StoragePrimaryKeyFile   string   `json:"storage_primary_key_file" mapstructure:"storage_primary_key_file"`

	// Keyshare attribute to issue during registration
	KeyshareAttribute irma.AttributeTypeIdentifier `json:"keyshare_attribute" mapstructure:"keyshare_attribute"`

	// Configuration for email sending during registration (email address use will be disabled if not present)
	keyshare.EmailConfiguration `mapstructure:",squash"`

	RegistrationEmailFiles     map[string]string `json:"registration_email_files" mapstructure:"registration_email_files"`
	RegistrationEmailSubject   map[string]string `json:"registration_email_subject" mapstructure:"registration_email_subject"`
	registrationEmailTemplates map[string]*template.Template

	VerificationURL map[string]string `json:"verification_url" mapstructure:"verification_url"`
}

func readAESKey(filename string) (uint32, keysharecore.AesKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, keysharecore.AesKey{}, err
	}
	if len(keyData) != 32+4 {
		return 0, keysharecore.AesKey{}, errors.New("Invalid aes key")
	}
	var key [32]byte
	copy(key[:], keyData[4:36])
	return binary.LittleEndian.Uint32(keyData[0:4]), key, nil
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) (*keysharecore.Core, error) {
	// Setup email templates
	var err error
	if conf.EmailServer != "" {
		conf.registrationEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.RegistrationEmailFiles,
			conf.RegistrationEmailSubject,
			conf.DefaultLanguage,
		)
		if err != nil {
			return nil, server.LogError(err)
		}
		if _, ok := conf.VerificationURL[conf.DefaultLanguage]; !ok {
			return nil, server.LogError(errors.Errorf("Missing verification base url for default language"))
		}
	}

	if err = conf.VerifyEmailServer(); err != nil {
		return nil, server.LogError(err)
	}

	// Setup database
	if conf.DB == nil {
		switch conf.DBType {
		case DatabaseTypeMemory:
			conf.DB = NewMemoryDatabase()
		case DatabaseTypePostgres:
			var err error
			conf.DB, err = NewPostgresDatabase(conf.DBConnstring)
			if err != nil {
				return nil, server.LogError(err)
			}
		default:
			return nil, server.LogError(ErrUnknownDatabaseType)
		}
	}

	// Setup IRMA session server url for in QR code
	conf.URL = keyshare.AppendURLPrefix(conf.URL, conf.PathPrefix)

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
	encID, encKey, err := readAESKey(conf.StoragePrimaryKeyFile)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to load primary storage key", 0))
	}

	core := keysharecore.NewKeyshareCore(encID, encKey, conf.JwtKeyID, jwtPrivateKey)
	for _, keyFile := range conf.StorageFallbackKeyFiles {
		id, key, err := readAESKey(keyFile)
		if err != nil {
			return nil, server.LogError(errors.WrapPrefix(err, "failed to load fallback key "+keyFile, 0))
		}
		core.DangerousAddAESKey(id, key)
	}

	return core, nil
}
