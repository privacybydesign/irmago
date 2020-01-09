package irmaclient

import (
	"github.com/privacybydesign/irmago/internal/test"
	"testing"
)

func TestConvertingLegacyStorage(t *testing.T) {
	test.SetTestStorageDir("legacy_teststorage")

	// Test all tests in this file with legacy storage too
	t.Run("TestVerify", TestVerify)
	t.Run("TestStorageDeserialization", TestStorageDeserialization)
	t.Run("TestCandidates", TestCandidates)
	t.Run("TestCandidateConjunctionOrder", TestCandidateConjunctionOrder)
	t.Run("TestCredentialRemoval", TestCredentialRemoval)
	t.Run("TestWrongSchemeManager", TestWrongSchemeManager)
	t.Run("TestCredentialInfoListNewAttribute", TestCredentialInfoListNewAttribute)
	// TestFreshStorage is not needed, because this test does not use an existing storage
	t.Run("TestKeyshareEnrollmentRemoval", TestKeyshareEnrollmentRemoval)
	t.Run("TestUpdatePreferences", TestUpdatePreferences)

	test.SetTestStorageDir("teststorage")
}
