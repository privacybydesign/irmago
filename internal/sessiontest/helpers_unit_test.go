// Unit tests for the disclosure plan assertion helpers (requireAttrsInOrder,
// requireDisclosurePlan, credMatchesExpected, requireCredentialDescriptor, findAttr).
//
// These helpers are used across the OpenID4VP integration tests to assert the
// structure of disclosure plans returned by the client. They've grown complex
// enough (ordered attribute matching, nested plan structure, multiple skip/check
// flags) that they need their own tests to prove correctness.
//
// Each helper has both happy-path tests (correct input passes) and failure tests
// (wrong input is properly rejected). Failure tests use a fakeT mock that
// captures require.FailNow panics without affecting the real test runner.
package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// TestTestHelpers is the single entry point for all helper unit tests.
// Run with: go test ./internal/sessiontest/ -run TestTestHelpers -v
func TestTestHelpers(t *testing.T) {
	t.Run("requireAttrsInOrder", testRequireAttrsInOrder)
	t.Run("requireAttrsInOrder_failures", testRequireAttrsInOrder_Failures)
	t.Run("credMatchesExpected", testCredMatchesExpected)
	t.Run("requireDisclosurePlan", testRequireDisclosurePlan)
	t.Run("requireDisclosurePlan_failures", testRequireDisclosurePlan_Failures)
	t.Run("requireCredentialDescriptor", testRequireCredentialDescriptor)
	t.Run("requireCredentialDescriptor_failures", testRequireCredentialDescriptor_Failures)
	t.Run("findAttr", testFindAttr)
}

// fakeT captures test failures without affecting the real test runner.
// It satisfies testingT (our helper interface) and require.TestingT.
type fakeT struct {
	failed bool
}

func (f *fakeT) Errorf(format string, args ...interface{}) { f.failed = true }
func (f *fakeT) FailNow()                                  { f.failed = true; panic(fakeFailNow{}) }
func (f *fakeT) Helper()                                   {}

type fakeFailNow struct{}

// shouldFail runs fn with a fakeT and asserts it triggers a failure.
func shouldFail(t *testing.T, name string, fn func(t testingT)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()
		ft := &fakeT{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(fakeFailNow); !ok {
						panic(r) // re-panic if not our sentinel
					}
				}
			}()
			fn(ft)
		}()
		if !ft.failed {
			t.Fatal("expected the helper to fail, but it passed")
		}
	})
}

// ---------------------------------------------------------------------------
// requireAttrsInOrder
// ---------------------------------------------------------------------------

func testRequireAttrsInOrder(t *testing.T) {
	t.Run("single attribute with all fields", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"}
		desc := clientmodels.TranslatedString{"en": "Your email address"}
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:   []any{"email"},
				DisplayName: &dn,
				Description: &desc,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("test@example.com")},
			},
		}
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your email address"},
			Value:       strVal("test@example.com"),
		})
	})

	t.Run("section header with nil value", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Address"}
		attrs := []clientmodels.Attribute{
			{ClaimPath: []any{"address"}, DisplayName: &dn, Value: nil},
		}
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:        []any{"address"},
			DisplayName: &clientmodels.TranslatedString{"en": "Address"},
			Value:       nil, // asserts actual Value is nil
		})
	})

	t.Run("value with string", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:   []any{"email"},
				DisplayName: &dn,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("foo@bar.com")},
			},
		}
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email"},
			Value:       strVal("foo@bar.com"),
		})
	})

	t.Run("requested value checked", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "University"}
		reqVal := &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("TU Delft")}
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:      []any{"university"},
				DisplayName:    &dn,
				RequestedValue: reqVal,
			},
		}
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:           []any{"university"},
			DisplayName:    &clientmodels.TranslatedString{"en": "University"},
			RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("TU Delft")},
		})
	})

	t.Run("nil display name asserts actual is nil", func(t *testing.T) {
		// Array items have nil DisplayName.
		attrs := []clientmodels.Attribute{
			{
				ClaimPath: []any{"courses", 0},
				Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Algorithms")},
			},
		}
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:  []any{"courses", 0},
			Value: strVal("Algorithms"),
			// DisplayName: nil → asserts actual.DisplayName is nil
		})
	})

	t.Run("nil description skips check", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		desc := clientmodels.TranslatedString{"en": "Your email"}
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:   []any{"email"},
				DisplayName: &dn,
				Description: &desc, // actual has a description
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")},
			},
		}
		// Expected Description is nil → skip the check (don't assert nil).
		requireAttrsInOrder(t, attrs, expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email"},
			Value:       strVal("a@b.com"),
			// Description: nil → skips check
		})
	})

	t.Run("multiple attributes in order", func(t *testing.T) {
		dn1 := clientmodels.TranslatedString{"en": "Given Name"}
		dn2 := clientmodels.TranslatedString{"en": "Email"}
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:   []any{"given_name"},
				DisplayName: &dn1,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Jan")},
			},
			{
				ClaimPath:   []any{"email"},
				DisplayName: &dn2,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("jan@example.com")},
			},
		}
		requireAttrsInOrder(t, attrs,
			expectedAttr{
				Path:        []any{"given_name"},
				DisplayName: &clientmodels.TranslatedString{"en": "Given Name"},
				Value:       strVal("Jan"),
			},
			expectedAttr{
				Path:        []any{"email"},
				DisplayName: &clientmodels.TranslatedString{"en": "Email"},
				Value:       strVal("jan@example.com"),
			},
		)
	})

	t.Run("bool and int values", func(t *testing.T) {
		dn1 := clientmodels.TranslatedString{"en": "Student"}
		dn2 := clientmodels.TranslatedString{"en": "Age"}
		b := true
		var age int64 = 25
		attrs := []clientmodels.Attribute{
			{
				ClaimPath:   []any{"is_student"},
				DisplayName: &dn1,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Bool, Bool: &b},
			},
			{
				ClaimPath:   []any{"age"},
				DisplayName: &dn2,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Int, Int: &age},
			},
		}
		requireAttrsInOrder(t, attrs,
			expectedAttr{
				Path:        []any{"is_student"},
				DisplayName: &clientmodels.TranslatedString{"en": "Student"},
				Value:       boolVal(true),
			},
			expectedAttr{
				Path:        []any{"age"},
				DisplayName: &clientmodels.TranslatedString{"en": "Age"},
				Value:       intVal(25),
			},
		)
	})
}

// ---------------------------------------------------------------------------
// credMatchesExpected
// ---------------------------------------------------------------------------

func testCredMatchesExpected(t *testing.T) {
	makeCred := func(id string, name clientmodels.TranslatedString, attrs ...clientmodels.Attribute) *clientmodels.SelectableCredentialInstance {
		return &clientmodels.SelectableCredentialInstance{
			CredentialId: id,
			Name:         name,
			Attributes:   attrs,
		}
	}

	emailAttr := clientmodels.Attribute{
		ClaimPath: []any{"email"},
		Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("test@example.com")},
	}

	t.Run("matches by id and attributes", func(t *testing.T) {
		name := clientmodels.TranslatedString{"en": "Email"}
		cred := makeCred("test.email", name, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Name:         name,
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.True(t, result)
	})

	t.Run("false when expected id empty but actual has id", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{"en": "Email"}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.False(t, result, "empty expected id should not match non-empty actual id")
	})

	t.Run("matches when both id empty", func(t *testing.T) {
		cred := makeCred("", nil, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.True(t, result)
	})

	t.Run("false when expected name empty but actual has name", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{"en": "Email"}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.False(t, result, "empty expected name should not match non-empty actual name")
	})

	t.Run("matches when both name empty", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{},
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.True(t, result)
	})

	t.Run("matches by name", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{"en": "Email", "nl": "E-mail"}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{"en": "Email", "nl": "E-mail"},
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.True(t, result)
	})

	t.Run("false on id mismatch", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.phone",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.False(t, result)
	})

	t.Run("false on name mismatch", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{"en": "Email"}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{"en": "Phone"},
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("test@example.com")}},
		})
		require.False(t, result)
	})

	t.Run("false on attribute count mismatch", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Attributes: []expectedAttr{
				{Path: []any{"email"}, Value: strVal("test@example.com")},
				{Path: []any{"domain"}, Value: strVal("example.com")},
			},
		})
		require.False(t, result)
	})

	t.Run("false on path mismatch", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Attributes:   []expectedAttr{{Path: []any{"phone"}, Value: strVal("test@example.com")}},
		})
		require.False(t, result)
	})

	t.Run("false on value mismatch", func(t *testing.T) {
		cred := makeCred("test.email", clientmodels.TranslatedString{}, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: strVal("wrong@example.com")}},
		})
		require.False(t, result)
	})

	t.Run("skips value comparison when expected nil", func(t *testing.T) {
		cred := makeCred("test.email", nil, emailAttr)
		result := credMatchesExpected(cred, expectedPlanCredential{
			CredentialId: "test.email",
			Attributes:   []expectedAttr{{Path: []any{"email"}, Value: nil}},
		})
		require.True(t, result)
	})
}

// ---------------------------------------------------------------------------
// requireDisclosurePlan
// ---------------------------------------------------------------------------

func testRequireDisclosurePlan(t *testing.T) {
	t.Run("nil choices asserts nil overview", func(t *testing.T) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: nil,
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: nil,
		})
	})

	t.Run("issuance steps", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				Steps: []clientmodels.IssuanceStep{
					{Options: []*clientmodels.CredentialDescriptor{
						{
							CredentialId: "test.email",
							Name:         clientmodels.TranslatedString{"en": "Email Cred"},
							Attributes: []clientmodels.Attribute{
								{
									ClaimPath:      []any{"email"},
									DisplayName:    &dn,
									RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								},
							},
						},
					}},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			IssuanceSteps: []expectedIssuanceStep{
				{Options: []expectedCredentialDescriptor{
					{
						CredentialId: "test.email",
						Name:         &clientmodels.TranslatedString{"en": "Email Cred"},
						Attributes: []expectedAttr{
							{
								Path:           []any{"email"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Email"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
				}},
			},
			Choices: nil,
		})
	})

	t.Run("issued credential ids", func(t *testing.T) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				IssuedCredentialIds: map[string]struct{}{"test.email": {}},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			IssuedCredentialIds: map[string]struct{}{"test.email": {}},
			Choices:             nil,
		})
	})

	t.Run("wrong credential issued nil", func(t *testing.T) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				WrongCredentialIssued: nil,
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			WrongCredentialIssuedNil: true,
			Choices:                  nil,
		})
	})

	t.Run("wrong credential issued", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "University"}
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				WrongCredentialIssued: &clientmodels.Credential{
					CredentialId: "test.studentCard",
					Attributes: []clientmodels.Attribute{
						{
							ClaimPath:   []any{"university"},
							DisplayName: &dn,
							Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Wrong Uni")},
						},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			WrongCredentialIssued: &expectedCredentialDescriptor{
				CredentialId: "test.studentCard",
				Attributes: []expectedAttr{
					{
						Path:        []any{"university"},
						DisplayName: &clientmodels.TranslatedString{"en": "University"},
						Value:       strVal("Wrong Uni"),
					},
				},
			},
			Choices: nil,
		})
	})

	t.Run("owned options matched", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					OwnedOptions: []*clientmodels.SelectableCredentialInstance{
						{
							CredentialId: "test.email",
							Name:         clientmodels.TranslatedString{"en": "Email Cred"},
							Attributes: []clientmodels.Attribute{
								{
									ClaimPath:   []any{"email"},
									DisplayName: &dn,
									Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")},
								},
							},
						},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Owned: []expectedPlanCredential{
						{
							CredentialId: "test.email",
							Name:         clientmodels.TranslatedString{"en": "Email Cred"},
							Attributes: []expectedAttr{
								{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")},
							},
						},
					},
				},
			},
		})
	})

	t.Run("obtainable options matched", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					ObtainableOptions: []*clientmodels.CredentialDescriptor{
						{
							CredentialId: "test.email",
							Name:         clientmodels.TranslatedString{"en": "Email Cred"},
							Attributes: []clientmodels.Attribute{
								{
									ClaimPath:      []any{"email"},
									DisplayName:    &dn,
									RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								},
							},
						},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Obtainable: []expectedCredentialDescriptor{
						{
							CredentialId: "test.email",
							Name:         &clientmodels.TranslatedString{"en": "Email Cred"},
							Attributes: []expectedAttr{
								{
									Path:           []any{"email"},
									DisplayName:    &clientmodels.TranslatedString{"en": "Email"},
									RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								},
							},
						},
					},
				},
			},
		})
	})

	t.Run("optional choice flag", func(t *testing.T) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{Optional: true},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Optional: true},
			},
		})
	})

	t.Run("multiple owned options finds correct match", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "University"}
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					OwnedOptions: []*clientmodels.SelectableCredentialInstance{
						{
							CredentialId: "sc",
							Name:         clientmodels.TranslatedString{"en": "Student Card"},
							Attributes: []clientmodels.Attribute{
								{ClaimPath: []any{"university"}, DisplayName: &dn, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Amsterdam")}},
							},
						},
						{
							CredentialId: "sc",
							Name:         clientmodels.TranslatedString{"en": "Student Card"},
							Attributes: []clientmodels.Attribute{
								{ClaimPath: []any{"university"}, DisplayName: &dn, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Delft")}},
							},
						},
					},
				},
			},
		}
		// Expect the Delft credential — credMatchesExpected should find it even though Amsterdam comes first.
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Owned: []expectedPlanCredential{
						{
							CredentialId: "sc",
							Name:         clientmodels.TranslatedString{"en": "Student Card"},
							Attributes: []expectedAttr{
								{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University"}, Value: strVal("Amsterdam")},
							},
						},
						{
							CredentialId: "sc",
							Name:         clientmodels.TranslatedString{"en": "Student Card"},
							Attributes: []expectedAttr{
								{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University"}, Value: strVal("Delft")},
							},
						},
					},
				},
			},
		})
	})

	t.Run("full plan with issuance and choices", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				Steps: []clientmodels.IssuanceStep{
					{Options: []*clientmodels.CredentialDescriptor{
						{CredentialId: "test.email"},
					}},
				},
				IssuedCredentialIds: map[string]struct{}{"test.email": {}},
			},
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					OwnedOptions: []*clientmodels.SelectableCredentialInstance{
						{
							CredentialId: "test.email",
							Attributes: []clientmodels.Attribute{
								{ClaimPath: []any{"email"}, DisplayName: &dn, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("x@y.com")}},
							},
						},
					},
					ObtainableOptions: []*clientmodels.CredentialDescriptor{
						{CredentialId: "test.email"},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			IssuanceSteps: []expectedIssuanceStep{
				{Options: []expectedCredentialDescriptor{{CredentialId: "test.email"}}},
			},
			IssuedCredentialIds: map[string]struct{}{"test.email": {}},
			Choices: []expectedPickOneChoice{
				{
					Owned: []expectedPlanCredential{
						{
							CredentialId: "test.email",
							Attributes: []expectedAttr{
								{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("x@y.com")},
							},
						},
					},
					Obtainable: []expectedCredentialDescriptor{
						{CredentialId: "test.email"},
					},
				},
			},
		})
	})
}

// ---------------------------------------------------------------------------
// requireCredentialDescriptor
// ---------------------------------------------------------------------------

func testRequireCredentialDescriptor(t *testing.T) {
	t.Run("matches id and name", func(t *testing.T) {
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{"en": "Email"},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.email",
			Name:         &clientmodels.TranslatedString{"en": "Email"},
		}, "test")
	})

	t.Run("skips id when empty", func(t *testing.T) {
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "anything",
			Name:         clientmodels.TranslatedString{"en": "Email"},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "", // skip
			Name:         &clientmodels.TranslatedString{"en": "Email"},
		}, "test")
	})

	t.Run("skips name when nil", func(t *testing.T) {
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{"en": "Whatever"},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.email",
			Name:         nil, // skip
		}, "test")
	})

	t.Run("checks attributes", func(t *testing.T) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "test.email",
			Attributes: []clientmodels.Attribute{
				{
					ClaimPath:      []any{"email"},
					DisplayName:    &dn,
					RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
					Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
				},
			},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.email",
			Attributes: []expectedAttr{
				{
					Path:           []any{"email"},
					DisplayName:    &clientmodels.TranslatedString{"en": "Email"},
					RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
					Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
				},
			},
		}, "test")
	})
}

// ---------------------------------------------------------------------------
// findAttr
// ---------------------------------------------------------------------------

func testFindAttr(t *testing.T) {
	dn1 := clientmodels.TranslatedString{"en": "Email"}
	dn2 := clientmodels.TranslatedString{"en": "Street"}
	attrs := []clientmodels.Attribute{
		{ClaimPath: []any{"email"}, DisplayName: &dn1, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")}},
		{ClaimPath: []any{"address", "street"}, DisplayName: &dn2, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Main St")}},
	}

	t.Run("finds by single path", func(t *testing.T) {
		result := findAttr(attrs, "email")
		require.NotNil(t, result)
		require.Equal(t, "a@b.com", *result.Value.String)
	})

	t.Run("finds by nested path", func(t *testing.T) {
		result := findAttr(attrs, "address", "street")
		require.NotNil(t, result)
		require.Equal(t, "Main St", *result.Value.String)
	})

	t.Run("returns nil when not found", func(t *testing.T) {
		result := findAttr(attrs, "phone")
		require.Nil(t, result)
	})
}

// ===========================================================================
// Failure tests — verify that helpers reject bad input
// ===========================================================================

func testRequireAttrsInOrder_Failures(t *testing.T) {
	dn := clientmodels.TranslatedString{"en": "Email"}
	emailAttr := clientmodels.Attribute{
		ClaimPath:   []any{"email"},
		DisplayName: &dn,
		Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")},
	}

	shouldFail(t, "wrong attribute count", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")},
			expectedAttr{Path: []any{"domain"}, DisplayName: &clientmodels.TranslatedString{"en": "Domain"}, Value: strVal("b.com")},
		)
	})

	shouldFail(t, "path mismatch", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"phone"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")},
		)
	})

	shouldFail(t, "value mismatch", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("wrong@b.com")},
		)
	})

	shouldFail(t, "value type mismatch", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: boolVal(true)},
		)
	})

	shouldFail(t, "expected value but actual is nil", func(t testingT) {
		noValue := clientmodels.Attribute{ClaimPath: []any{"email"}, DisplayName: &dn, Value: nil}
		requireAttrsInOrder(t, []clientmodels.Attribute{noValue},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")},
		)
	})

	shouldFail(t, "expected nil value (header) but actual has value", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: nil},
		)
	})

	shouldFail(t, "display name expected non-nil but actual is nil", func(t testingT) {
		noDisplayName := clientmodels.Attribute{
			ClaimPath: []any{"email"},
			Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")},
		}
		requireAttrsInOrder(t, []clientmodels.Attribute{noDisplayName},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")},
		)
	})

	shouldFail(t, "display name expected nil but actual is non-nil", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, Value: strVal("a@b.com")}, // DisplayName nil → asserts actual nil
		)
	})

	shouldFail(t, "display name locale mismatch", func(t testingT) {
		requireAttrsInOrder(t, []clientmodels.Attribute{emailAttr},
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Wrong Name"}, Value: strVal("a@b.com")},
		)
	})

	shouldFail(t, "description mismatch", func(t testingT) {
		desc := clientmodels.TranslatedString{"en": "Actual description"}
		attrWithDesc := clientmodels.Attribute{
			ClaimPath:   []any{"email"},
			DisplayName: &dn,
			Description: &desc,
			Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")},
		}
		requireAttrsInOrder(t, []clientmodels.Attribute{attrWithDesc},
			expectedAttr{
				Path:        []any{"email"},
				DisplayName: &clientmodels.TranslatedString{"en": "Email"},
				Description: &clientmodels.TranslatedString{"en": "Wrong description"},
				Value:       strVal("a@b.com"),
			},
		)
	})

	shouldFail(t, "requested value mismatch", func(t testingT) {
		reqVal := &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("actual")}
		attrWithReq := clientmodels.Attribute{
			ClaimPath:      []any{"email"},
			DisplayName:    &dn,
			Value:          nil,
			RequestedValue: reqVal,
		}
		requireAttrsInOrder(t, []clientmodels.Attribute{attrWithReq},
			expectedAttr{
				Path:           []any{"email"},
				DisplayName:    &clientmodels.TranslatedString{"en": "Email"},
				Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
				RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("expected")},
			},
		)
	})

	shouldFail(t, "requested value expected but actual is nil", func(t testingT) {
		attrNoReq := clientmodels.Attribute{
			ClaimPath:   []any{"email"},
			DisplayName: &dn,
			Value:       nil,
		}
		requireAttrsInOrder(t, []clientmodels.Attribute{attrNoReq},
			expectedAttr{
				Path:           []any{"email"},
				DisplayName:    &clientmodels.TranslatedString{"en": "Email"},
				Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
				RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
			},
		)
	})
}

func testRequireDisclosurePlan_Failures(t *testing.T) {
	shouldFail(t, "nil plan", func(t testingT) {
		requireDisclosurePlan(t, nil, expectedDisclosurePlan{Choices: nil})
	})

	shouldFail(t, "expected nil choices but actual has choices", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{{}},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{Choices: nil})
	})

	shouldFail(t, "expected choices but actual is nil", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: nil,
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{{}},
		})
	})

	shouldFail(t, "choice count mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{{}, {}},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{{}},
		})
	})

	shouldFail(t, "owned option count mismatch", func(t testingT) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					OwnedOptions: []*clientmodels.SelectableCredentialInstance{
						{
							CredentialId: "test.email",
							Attributes: []clientmodels.Attribute{
								{ClaimPath: []any{"email"}, DisplayName: &dn, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")}},
							},
						},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Owned: []expectedPlanCredential{
						{Attributes: []expectedAttr{{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("a@b.com")}}},
						{Attributes: []expectedAttr{{Path: []any{"phone"}, DisplayName: &clientmodels.TranslatedString{"en": "Phone"}, Value: strVal("123")}}},
					},
				},
			},
		})
	})

	shouldFail(t, "no owned option matches expected", func(t testingT) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					OwnedOptions: []*clientmodels.SelectableCredentialInstance{
						{
							CredentialId: "test.email",
							Attributes: []clientmodels.Attribute{
								{ClaimPath: []any{"email"}, DisplayName: &dn, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("a@b.com")}},
							},
						},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Owned: []expectedPlanCredential{
						{Attributes: []expectedAttr{{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("wrong@b.com")}}},
					},
				},
			},
		})
	})

	shouldFail(t, "obtainable option count mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					ObtainableOptions: []*clientmodels.CredentialDescriptor{
						{CredentialId: "test.email"},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Obtainable: []expectedCredentialDescriptor{
						{CredentialId: "test.email"},
						{CredentialId: "test.phone"},
					},
				},
			},
		})
	})

	shouldFail(t, "issuance step count mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				Steps: []clientmodels.IssuanceStep{{}, {}},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			IssuanceSteps: []expectedIssuanceStep{{}},
			Choices:       nil,
		})
	})

	shouldFail(t, "issued credential ids mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				IssuedCredentialIds: map[string]struct{}{"test.email": {}},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			IssuedCredentialIds: map[string]struct{}{"test.phone": {}},
			Choices:             nil,
		})
	})

	shouldFail(t, "wrong credential expected nil but is non-nil", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				WrongCredentialIssued: &clientmodels.Credential{CredentialId: "test.email"},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			WrongCredentialIssuedNil: true,
			Choices:                  nil,
		})
	})

	shouldFail(t, "wrong credential expected non-nil but is nil", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			IssueDuringDisclosure: &clientmodels.IssueDuringDisclosure{
				WrongCredentialIssued: nil,
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			WrongCredentialIssued: &expectedCredentialDescriptor{CredentialId: "test.email"},
			Choices:               nil,
		})
	})

	shouldFail(t, "optional flag mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{Optional: false},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Optional: true},
			},
		})
	})

	shouldFail(t, "obtainable credential id mismatch", func(t testingT) {
		plan := &clientmodels.DisclosurePlan{
			DisclosureChoicesOverview: []clientmodels.DisclosurePickOne{
				{
					ObtainableOptions: []*clientmodels.CredentialDescriptor{
						{CredentialId: "test.email"},
					},
				},
			},
		}
		requireDisclosurePlan(t, plan, expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{
					Obtainable: []expectedCredentialDescriptor{
						{CredentialId: "test.phone"},
					},
				},
			},
		})
	})
}

func testRequireCredentialDescriptor_Failures(t *testing.T) {
	shouldFail(t, "credential id mismatch", func(t testingT) {
		desc := &clientmodels.CredentialDescriptor{CredentialId: "test.email"}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.phone",
		}, "test")
	})

	shouldFail(t, "name mismatch", func(t testingT) {
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "test.email",
			Name:         clientmodels.TranslatedString{"en": "Email"},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.email",
			Name:         &clientmodels.TranslatedString{"en": "Phone"},
		}, "test")
	})

	shouldFail(t, "attribute mismatch", func(t testingT) {
		dn := clientmodels.TranslatedString{"en": "Email"}
		desc := &clientmodels.CredentialDescriptor{
			CredentialId: "test.email",
			Attributes: []clientmodels.Attribute{
				{ClaimPath: []any{"email"}, DisplayName: &dn},
			},
		}
		requireCredentialDescriptor(t, desc, expectedCredentialDescriptor{
			CredentialId: "test.email",
			Attributes: []expectedAttr{
				{Path: []any{"phone"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}},
			},
		}, "test")
	})
}
