package irmaclient

import (
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
)

func TestConvertingLegacyStorage(t *testing.T) {
	test.SetTestStorageDir("client_legacy")
	defer test.SetTestStorageDir("client")

	// Test all tests in this file with legacy storage too
	t.Run("TestStorageDeserialization", TestStorageDeserialization)
	t.Run("TestCandidates", TestCandidates)
	t.Run("TestCandidateConjunctionOrder", TestCandidateConjunctionOrder)
	t.Run("TestCredentialRemoval", TestCredentialRemoval)
	t.Run("TestWrongSchemeManager", TestWrongSchemeManager)
	t.Run("TestCredentialInfoListNewAttribute", TestCredentialInfoListNewAttribute)
	// TestFreshStorage is not needed, because this test does not use an existing storage
	t.Run("TestKeyshareEnrollmentRemoval", TestKeyshareEnrollmentRemoval)
	t.Run("TestUpdatingStorage", TestUpdatingStorage)
	t.Run("TestRemoveStorage", TestRemoveStorage)
}
