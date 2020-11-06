package keysharemigrate

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"io/ioutil"

	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
)

type Configuration struct {
	SourceConn            string `json:"source_conn" mapstructure:"source_conn"`
	DestConn              string `json:"dest_conn" mapstructure:"dest_conn"`
	StoragePrimaryKeyFile string `json:"storage_primary_key_file" mapstructure:"storage_primary_key_file"`
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

func New(c *Configuration) *Converter {
	logger := server.NewLogger(3, false, false)

	source_db, err := sql.Open("pgx", c.SourceConn)
	if err != nil {
		logger.WithField("error", err).Fatal("Could not open connection to source database.")
	}

	target_db, err := sql.Open("pgx", c.DestConn)
	if err != nil {
		logger.WithField("error", err).Fatal("Could not open connection to destination database.")
	}

	core := keysharecore.NewKeyshareCore()
	index, key, err := readAESKey(c.StoragePrimaryKeyFile)
	if err != nil {
		logger.WithField("error", err).Fatal("Could not load storage key.")
	}
	core.DangerousSetAESEncryptionKey(index, key)

	return &Converter{
		source_db: source_db,
		target_db: target_db,
		core:      core,
		logger:    logger,
	}
}
