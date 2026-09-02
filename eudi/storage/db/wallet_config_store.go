package db

import (
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

// WalletConfigStore persists signed wallet configs in the wallet_config_documents
// table, one per environment. It satisfies walletconfig.Store structurally, which
// is how the wallet hands it to the config manager; naming that interface here
// would make this package depend on the eudi packages.
type WalletConfigStore struct {
	db *gorm.DB
}

func NewWalletConfigStore(db *gorm.DB) *WalletConfigStore {
	return &WalletConfigStore{db: db}
}

// Get implements walletconfig.Store. Any read failure reads as a miss: the caller
// falls back to its bundled config or a fetch, and the interface has nowhere to
// report an error to.
func (s *WalletConfigStore) Get(environment string) ([]byte, bool) {
	if environment == "" {
		return nil, false
	}
	var row models.WalletConfigDocument
	if err := s.db.First(&row, "environment = ?", environment).Error; err != nil {
		return nil, false
	}
	return row.RawJws, true
}

// Put implements walletconfig.Store, replacing whatever the environment held.
func (s *WalletConfigStore) Put(environment string, rawJws []byte) error {
	if environment == "" {
		return fmt.Errorf("wallet_config_documents: empty environment")
	}
	if len(rawJws) == 0 {
		return fmt.Errorf("wallet_config_documents: empty document")
	}
	return s.db.Save(&models.WalletConfigDocument{
		Environment: environment,
		RawJws:      rawJws,
		FetchedAt:   time.Now(),
	}).Error
}
