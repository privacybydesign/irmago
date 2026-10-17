package clientmodels

import "time"

// WalletProviderTransaction is one entry of the wallet provider transaction
// log: an operation the wallet provider performed for this wallet unit. It is
// shown apart from the activity log (CONTEXT.md, "Wallet provider transaction
// log"), and never names the verifier of a disclosure.
type WalletProviderTransaction struct {
	ID string `json:"id"`
	// Time is when the provider performed the operation.
	Time time.Time `json:"time"`
	// Operation is "activate", "unlock", "generate-keys", "sign",
	// "remove-keys", "change-pin", "rejected" (refused for a wrong or blocked
	// PIN: someone tried the PIN) or "other".
	Operation string `json:"operation"`
	// Purpose is the declared purpose of a signature: "issuance-pop" or
	// "disclosure-kb", when recorded.
	Purpose string `json:"purpose,omitempty"`
	// Counterparty and CredentialType name the issuer and credential type of
	// an issuance signature, when recorded.
	Counterparty   string `json:"counterparty,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	Succeeded      bool   `json:"succeeded"`
}
