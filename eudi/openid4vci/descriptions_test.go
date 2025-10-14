package openid4vci

import (
	"testing"
)

func TestCredentialResponse_Validate(t *testing.T) {
	transactionID := "tx123"
	interval := 30

	tests := []struct {
		name     string // description of this test case
		c        *CredentialResponse
		deferred bool
		wantErr  bool
	}{
		{
			name: "deferred response with credentials - invalid",
			c: &CredentialResponse{
				Credentials: []CredentialInstance{
					{Credential: "cred1"},
				},
			},
			deferred: true,
			wantErr:  true,
		},
		{
			name: "deferred response with credentials and transaction details - invalid",
			c: &CredentialResponse{
				Credentials: []CredentialInstance{
					{Credential: "cred1"},
				},
				TransactionId: &transactionID,
				Interval:      &interval,
			},
			deferred: true,
			wantErr:  true,
		},
		{
			name:     "deferred response without transaction details - invalid",
			c:        &CredentialResponse{},
			deferred: true,
			wantErr:  true,
		},
		{
			name: "deferred response with transaction id, without interval - invalid",
			c: &CredentialResponse{
				TransactionId: &transactionID,
			},
			deferred: true,
			wantErr:  true,
		},
		{
			name: "deferred response with transaction id and interval - valid",
			c: &CredentialResponse{
				TransactionId: &transactionID,
				Interval:      &interval,
			},
			deferred: true,
			wantErr:  false,
		},
		{
			name: "immediate response without credentials - invalid",
			c: &CredentialResponse{
				Credentials: []CredentialInstance{},
			},
			deferred: false,
			wantErr:  true,
		},
		{
			name: "immediate response with credentials and transaction details - invalid",
			c: &CredentialResponse{
				Credentials: []CredentialInstance{
					{Credential: "cred1"},
				},
				TransactionId: &transactionID,
				Interval:      &interval,
			},
			deferred: false,
			wantErr:  true,
		},
		{
			name: "immediate response with transaction details - invalid",
			c: &CredentialResponse{
				TransactionId: &transactionID,
				Interval:      &interval,
			},
			deferred: false,
			wantErr:  true,
		},
		{
			name: "immediate response with credentials - valid",
			c: &CredentialResponse{
				Credentials: []CredentialInstance{
					{Credential: "cred1"},
				},
			},
			deferred: false,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.c.Validate(tt.deferred)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Validate() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Validate() succeeded unexpectedly")
			}
		})
	}
}
