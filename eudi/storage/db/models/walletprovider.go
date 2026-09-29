package models

// WalletProviderValue is one entry of the wallet provider's own key-value
// store (walletprovider.Host.Storage). The values are opaque to the wallet;
// the SQLCipher layer encrypts them at rest like everything else here.
type WalletProviderValue struct {
	Key   string `gorm:"primaryKey"`
	Value []byte `gorm:"type:bytea;not null"`
}

func (WalletProviderValue) TableName() string { return "wallet_provider_values" }
