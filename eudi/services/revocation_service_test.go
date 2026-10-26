package services

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/stretchr/testify/assert"
)

// IsStoredStatusRevoked is the one revocation policy every read path uses:
// anything other than valid is revoked, except unknown (not yet checked).
func Test_RevocationService_IsStoredStatusRevoked(t *testing.T) {
	rc := NewRevocationService(nil)
	for status, want := range map[statuslist.Status]bool{
		statuslist.StatusValid:               false,
		statuslist.StatusInvalid:             true,
		statuslist.StatusSuspended:           true,
		statuslist.StatusApplicationSpecific: true,
		statuslist.StatusUnknown:             false,
	} {
		assert.Equal(t, want, rc.IsStoredStatusRevoked(uint8(status)), "status %v", status)
	}
}
