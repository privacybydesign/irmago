package sdjwtvc

import (
	"testing"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/stretchr/testify/require"
)

func buildTestSdJwtWithNestedClaims(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "TestCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Alice"),
			SdClaim("family_name", "Smith"),
			SdObject("address",
				SdClaim("street", "123 Main St"),
				SdClaim("city", "Amsterdam"),
				SdClaim("country", "NL"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_SelectTopLevelClaim(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "address")
}

func TestCreatePresentation_SelectMultipleTopLevelClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}, {"family_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "address")
}

func TestCreatePresentation_SelectNestedClaim(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"address", "street"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// Should include the parent "address" disclosure and the nested "street" disclosure.
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "street")
	require.NotContains(t, disclosures, "city")
	require.NotContains(t, disclosures, "country")
}

func TestCreatePresentation_SelectMultipleNestedClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"address", "street"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "street")
	require.Contains(t, disclosures, "city")
	require.NotContains(t, disclosures, "country")
}

func TestCreatePresentation_MixTopLevelAndNested(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"given_name"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "city")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "street")
}

func TestCreatePresentation_EmptyPaths_NoDisclosures(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_NonExistentClaim_NoError(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"nonexistent"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_DuplicatePaths_NoDuplicateDisclosures(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"address", "street"},
		{"address", "street"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// "address" should appear only once even though two paths traverse it.
	count := 0
	for _, k := range disclosures {
		if k == "address" {
			count++
		}
	}
	require.Equal(t, 1, count, "address disclosure should appear exactly once")
}

// --- SD-JWTs with mixed SD and non-SD claims ---

// buildMixedSdJwt has top-level claims where some are SD and some are plaintext.
func buildMixedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "MixedCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("email", "alice@example.com"),   // SD
			Claim("nickname", "Ali"),                // plaintext (not SD)
			SdClaim("phone_number", "+31612345678"), // SD
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

// buildMixedNestedSdJwt has a non-SD object containing SD sub-claims, and
// an SD object containing a mix of SD and non-SD sub-claims.
func buildMixedNestedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "MixedNestedCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Bob"),
			// Non-SD object with SD sub-claims: address is always visible,
			// but its children are selectively disclosable.
			Object("address",
				SdClaim("street", "456 Oak Ave"),
				Claim("country", "NL"), // plaintext inside the object
				SdClaim("city", "Rotterdam"),
			),
			// SD object with a mix of SD and non-SD sub-claims.
			SdObject("employment",
				Claim("company", "Acme Corp"), // plaintext inside SD object
				SdClaim("title", "Engineer"),
				SdClaim("salary", "100000"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_Mixed_SelectSdClaim_SkipsPlaintext(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"email"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "email")
	require.NotContains(t, disclosures, "phone_number")
	// "nickname" is plaintext — it should never appear as a disclosure.
	require.NotContains(t, disclosures, "nickname")
}

func TestCreatePresentation_Mixed_SelectPlaintextClaim_NoDisclosure(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	// "nickname" is not selectively disclosed; requesting it yields no disclosures.
	result, err := CreatePresentation(sdJwt, [][]any{{"nickname"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_Mixed_SelectAllSdClaims(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"email"}, {"phone_number"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "email")
	require.Contains(t, disclosures, "phone_number")
	require.Len(t, disclosures, 2)
}

func TestCreatePresentation_MixedNested_NonSdParent_SelectSdChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "address" is a non-SD object, so no disclosure for it.
	// "street" inside address is SD.
	result, err := CreatePresentation(sdJwt, [][]any{{"address", "street"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "street")
	// "address" itself is not SD — no disclosure for it.
	require.NotContains(t, disclosures, "address")
	require.NotContains(t, disclosures, "city")
}

func TestCreatePresentation_MixedNested_NonSdParent_SelectPlaintextChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "country" inside "address" is plaintext — no disclosure needed.
	result, err := CreatePresentation(sdJwt, [][]any{{"address", "country"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_MixedNested_SdParent_SelectSdChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "employment" is an SD object, "title" inside it is also SD.
	result, err := CreatePresentation(sdJwt, [][]any{{"employment", "title"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "employment")
	require.Contains(t, disclosures, "title")
	require.NotContains(t, disclosures, "salary")
	require.NotContains(t, disclosures, "company")
}

func TestCreatePresentation_MixedNested_SdParent_SelectPlaintextChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "company" inside "employment" is plaintext, but "employment" itself is SD.
	// Selecting the plaintext child should still include the parent disclosure.
	result, err := CreatePresentation(sdJwt, [][]any{{"employment", "company"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// The parent "employment" disclosure is needed to reveal the object.
	require.Contains(t, disclosures, "employment")
	// "company" is plaintext — no separate disclosure for it.
	require.NotContains(t, disclosures, "company")
}

func TestCreatePresentation_MixedNested_CombinedPaths(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{
		{"given_name"},
		{"address", "street"},
		{"address", "city"},
		{"employment", "title"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "street")
	require.Contains(t, disclosures, "city")
	require.Contains(t, disclosures, "employment")
	require.Contains(t, disclosures, "title")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "salary")
}

// --- SD-JWTs with array claims ---

// buildSdJwtWithArrays has:
//   - "tags": a non-SD array with mixed SD/non-SD items
//   - "roles": an SD array (the array itself is selectively disclosed)
//   - "scores": a plaintext array (non-SD, non-SD items)
func buildSdJwtWithArrays(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "ArrayCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("name", "Charlie"),
			// Non-SD array containing a mix of SD and non-SD items.
			Array("tags",
				Item("public-tag"),
				SdItem("secret-tag"),
				Item("another-public"),
			),
			// SD array: the entire array is selectively disclosed.
			SdArray("roles",
				Item("admin"),
				Item("editor"),
			),
			// Plaintext array with only non-SD items.
			Array("scores",
				Item(90),
				Item(85),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

// buildSdJwtWithNestedArrayInObject has an object containing an SD array.
func buildSdJwtWithNestedArrayInObject(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "NestedArrayCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdObject("profile",
				SdClaim("username", "charlie"),
				SdArray("permissions",
					Item("read"),
					Item("write"),
				),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_SdArray_SelectByKey(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "roles" is an SD array — selecting it should include its disclosure.
	result, err := CreatePresentation(sdJwt, [][]any{{"roles"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "roles")
	require.NotContains(t, disclosures, "name")
}

func TestCreatePresentation_SdArrayElement_SelectByIndex(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "tags" is a non-SD array with an SD element at index 1 ("secret-tag").
	// Selecting ["tags", 1] should include the disclosure for that element.
	result, err := CreatePresentation(sdJwt, [][]any{{"tags", 1}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Len(t, disclosures, 1)
	require.Equal(t, "", disclosures[0].Key, "array element disclosures have empty keys")
	require.Equal(t, "secret-tag", disclosures[0].Value)
}

func TestCreatePresentation_SdArrayElement_NonSdIndex_NoDisclosure(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "tags" index 0 is a non-SD item ("public-tag") — no disclosure needed.
	result, err := CreatePresentation(sdJwt, [][]any{{"tags", 0}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_SdArrayElement_OutOfBounds_NoError(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// Index 99 is out of bounds — should not error, just produce no disclosures.
	result, err := CreatePresentation(sdJwt, [][]any{{"tags", 99}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_SdArrayElement_MultipleIndices(t *testing.T) {
	// Build an array with multiple SD items.
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "MultiSdArray"),
			Claim(Key_IssuedAt, 1700000000),
			Array("items",
				SdItem("first"),
				SdItem("second"),
				SdItem("third"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)

	// Select index 0 and 2 — should include 2 disclosures with correct values.
	result, err := CreatePresentation(sdJwt, [][]any{{"items", 0}, {"items", 2}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Len(t, disclosures, 2)

	values := make([]string, len(disclosures))
	for i, d := range disclosures {
		values[i] = d.Value.(string)
	}
	require.Contains(t, values, "first")
	require.Contains(t, values, "third")
	require.NotContains(t, values, "second")
}

// buildComplexNestedSdJwt builds a deeply nested SD-JWT:
//
//	Top-level SD claims: "org_name"
//	"projects" (SD object containing):
//	  - "project_name" (SD claim)
//	  - "team" (non-SD array with SD items: employee names)
//	  - "budget" (SD claim)
//	"tags" (non-SD array with SD items: tag strings)
//
// This tests the combination of SD objects → arrays with SD elements → scalar values.
func buildComplexNestedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "OrgCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("org_name", "ACME Corp"),
			SdObject("projects",
				SdClaim("project_name", "Phoenix"),
				Array("team",
					SdItem("Alice"),
					SdItem("Bob"),
					Item("Charlie"), // non-SD
				),
				SdClaim("budget", "1000000"),
			),
			Array("tags",
				SdItem("confidential"),
				Item("public"),
				SdItem("internal"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_ComplexNested_SelectNestedSdArrayElement(t *testing.T) {
	sdJwt := buildComplexNestedSdJwt(t)

	// Select a single employee from the nested "team" array inside SD object "projects".
	// Path: ["projects", "team", 0] → should include "projects" (parent) + "Alice" (array elem)
	result, err := CreatePresentation(sdJwt, [][]any{{"projects", "team", 0}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Len(t, disclosures, 2) // "projects" parent + "Alice" array element

	projectsDisc := findDisclosure(t, disclosures, "projects")
	require.NotNil(t, projectsDisc.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Len(t, arrayElems, 1)
	require.Equal(t, "Alice", arrayElems[0].Value)
}

func TestCreatePresentation_ComplexNested_SelectMultipleNestedArrayElements(t *testing.T) {
	sdJwt := buildComplexNestedSdJwt(t)

	// Select both SD employees from "team": index 0 (Alice) and 1 (Bob), skip non-SD index 2 (Charlie).
	result, err := CreatePresentation(sdJwt, [][]any{
		{"projects", "team", 0},
		{"projects", "team", 1},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Len(t, disclosures, 3) // "projects" parent + 2 array elements

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Len(t, arrayElems, 2)
	values := []string{arrayElems[0].Value.(string), arrayElems[1].Value.(string)}
	require.Contains(t, values, "Alice")
	require.Contains(t, values, "Bob")
}

func TestCreatePresentation_ComplexNested_NonSdArrayIndex_NoExtraDisclosure(t *testing.T) {
	sdJwt := buildComplexNestedSdJwt(t)

	// "team" index 2 is non-SD ("Charlie") — only the parent "projects" disclosure is needed.
	result, err := CreatePresentation(sdJwt, [][]any{{"projects", "team", 2}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	// Only the "projects" parent is disclosed, "Charlie" is plaintext.
	require.Len(t, disclosures, 1)
	require.Equal(t, "projects", disclosures[0].Key)
}

func TestCreatePresentation_ComplexNested_MixScalarAndArrayElementPaths(t *testing.T) {
	sdJwt := buildComplexNestedSdJwt(t)

	// Select:
	// - top-level SD claim "org_name"
	// - nested SD claim "projects" → "project_name"
	// - nested SD array element "projects" → "team" → index 1 (Bob)
	// - top-level array SD element "tags" → index 0 ("confidential")
	result, err := CreatePresentation(sdJwt, [][]any{
		{"org_name"},
		{"projects", "project_name"},
		{"projects", "team", 1},
		{"tags", 0},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected disclosures:
	// 1. "org_name" = "ACME Corp"
	// 2. "projects" (parent, included because children are SD)
	// 3. "project_name" = "Phoenix"
	// 4. array element "Bob" (from team index 1)
	// 5. array element "confidential" (from tags index 0)
	require.Len(t, disclosures, 5)

	orgName := findDisclosure(t, disclosures, "org_name")
	require.Equal(t, "ACME Corp", orgName.Value)

	projectName := findDisclosure(t, disclosures, "project_name")
	require.Equal(t, "Phoenix", projectName.Value)

	projectsParent := findDisclosure(t, disclosures, "projects")
	require.NotNil(t, projectsParent.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Len(t, arrayElems, 2)
	elemValues := []string{arrayElems[0].Value.(string), arrayElems[1].Value.(string)}
	require.Contains(t, elemValues, "Bob")
	require.Contains(t, elemValues, "confidential")
}

func TestCreatePresentation_ComplexNested_SelectBudgetSkipsTeam(t *testing.T) {
	sdJwt := buildComplexNestedSdJwt(t)

	// Select only "budget" from within "projects" — should NOT include any team member disclosures.
	result, err := CreatePresentation(sdJwt, [][]any{{"projects", "budget"}})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)
	require.Len(t, disclosures, 2) // "projects" parent + "budget"

	budget := findDisclosure(t, disclosures, "budget")
	require.Equal(t, "1000000", budget.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Empty(t, arrayElems, "no array element disclosures should be present")
}

// buildDeeplyNestedSdJwt creates a structure that nests objects inside arrays
// inside objects to stress-test the path walker:
//
//	"university" (SD object):
//	  "name": "TU Delft" (SD claim)
//	  "faculties" (non-SD array):
//	    [0]: SD object (faculty):
//	      "faculty_name": "EEMCS" (SD claim)
//	      "departments" (non-SD array):
//	        [0]: SD object (department):
//	          "dept_name": "Software Technology" (SD claim)
//	          "courses" (non-SD array):
//	            [0]: SdItem "Compiler Construction"
//	            [1]: SdItem "Distributed Systems"
//	            [2]: Item "Intro to CS" (non-SD)
//	        [1]: Item "Applied Mathematics" (non-SD plain string)
//	    [1]: SD object (faculty):
//	      "faculty_name": "Architecture" (SD claim)
//	      "departments" (non-SD array):
//	        [0]: SdItem "Urbanism"
func buildDeeplyNestedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "UniversityCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdObject("university",
				SdClaim("name", "TU Delft"),
				Array("faculties",
					// Faculty 0: EEMCS with nested departments and courses
					SdObject("",
						SdClaim("faculty_name", "EEMCS"),
						Array("departments",
							SdObject("",
								SdClaim("dept_name", "Software Technology"),
								Array("courses",
									SdItem("Compiler Construction"),
									SdItem("Distributed Systems"),
									Item("Intro to CS"),
								),
							),
							Item("Applied Mathematics"),
						),
					),
					// Faculty 1: Architecture with one department
					SdObject("",
						SdClaim("faculty_name", "Architecture"),
						Array("departments",
							SdItem("Urbanism"),
						),
					),
				),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_DeepNested_SelectCourseAtDepth5(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// Path: university → faculties[0] → departments[0] → courses[0]
	// This navigates 5 levels deep: SD object → array → SD object → array → SD item
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "faculties", 0, "departments", 0, "courses", 0},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" (parent) + faculty[0] (SD array elem) +
	// department[0] (SD array elem) + "Compiler Construction" (SD array elem)
	require.Len(t, disclosures, 4)

	uni := findDisclosure(t, disclosures, "university")
	require.NotNil(t, uni.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Len(t, arrayElems, 3)

	// One of the array element values should be the course name.
	var values []any
	for _, d := range arrayElems {
		values = append(values, d.Value)
	}
	require.Contains(t, values, "Compiler Construction")
}

func TestCreatePresentation_DeepNested_SelectMultipleCoursesFromSameDepartment(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// Select courses[0] and courses[1] from the same department.
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "faculties", 0, "departments", 0, "courses", 0},
		{"university", "faculties", 0, "departments", 0, "courses", 1},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" + faculty[0] + department[0] + 2 courses
	// Parent disclosures should not be duplicated.
	require.Len(t, disclosures, 5)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	var courseValues []any
	for _, d := range arrayElems {
		courseValues = append(courseValues, d.Value)
	}
	require.Contains(t, courseValues, "Compiler Construction")
	require.Contains(t, courseValues, "Distributed Systems")
}

func TestCreatePresentation_DeepNested_SelectNonSdCourseIndex_OnlyParentsDisclosed(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// courses[2] is non-SD ("Intro to CS") — only parent disclosures needed.
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "faculties", 0, "departments", 0, "courses", 2},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" + faculty[0] + department[0] (parents only, no course disclosure)
	require.Len(t, disclosures, 3)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	// Faculty and department are SD object array elements, but no course element.
	require.Len(t, arrayElems, 2)
}

func TestCreatePresentation_DeepNested_SelectFacultyName(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// Select just the faculty name from the second faculty (Architecture).
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "faculties", 1, "faculty_name"},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" + faculty[1] (SD array elem) + "faculty_name"
	require.Len(t, disclosures, 3)

	facultyName := findDisclosure(t, disclosures, "faculty_name")
	require.Equal(t, "Architecture", facultyName.Value)
}

func TestCreatePresentation_DeepNested_SelectAcrossBothFaculties(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// Select faculty_name from faculty[0] AND a department from faculty[1].
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "faculties", 0, "faculty_name"},
		{"university", "faculties", 1, "departments", 0},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" + faculty[0] + "faculty_name"="EEMCS" +
	//           faculty[1] + "Urbanism" (SD array elem in Architecture's departments)
	require.Len(t, disclosures, 5)

	facultyName := findDisclosure(t, disclosures, "faculty_name")
	require.Equal(t, "EEMCS", facultyName.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	// 2 faculty elements + 1 department/course element
	require.Len(t, arrayElems, 3)

	var elemValues []any
	for _, d := range arrayElems {
		elemValues = append(elemValues, d.Value)
	}
	require.Contains(t, elemValues, "Urbanism")
}

func TestCreatePresentation_DeepNested_SelectUniversityNameOnly(t *testing.T) {
	sdJwt := buildDeeplyNestedSdJwt(t)

	// Select only the university name — nothing from faculties.
	result, err := CreatePresentation(sdJwt, [][]any{
		{"university", "name"},
	})

	require.NoError(t, err)
	disclosures := extractDecodedDisclosures(t, result)

	// Expected: "university" (parent) + "name"
	require.Len(t, disclosures, 2)

	name := findDisclosure(t, disclosures, "name")
	require.Equal(t, "TU Delft", name.Value)

	arrayElems := findArrayElementDisclosures(t, disclosures)
	require.Empty(t, arrayElems, "no faculty or course disclosures should leak")
}

// TestValidateDisclosureDependencies_MissingParent tests that the validation
// catches a disclosure that is not reachable from the top-level payload.
// This simulates a bug where a child disclosure is selected without its parent.
func TestValidateDisclosureDependencies_MissingParent(t *testing.T) {
	// Simulate a payload with a nested SD structure:
	//   top-level _sd contains hash for "parent" disclosure
	//   "parent" disclosure reveals an object with its own _sd containing hash for "child"
	parentHash := "parent-hash-123"
	childHash := "child-hash-456"

	payload := map[string]any{
		Key_Sd: []any{parentHash},
	}

	byHash := map[string]indexedDisclosure{
		parentHash: {
			decoded: DisclosureContent{Key: "parent", Value: map[string]any{
				Key_Sd: []any{childHash},
			}},
		},
		childHash: {
			decoded: DisclosureContent{Key: "child", Value: "secret"},
		},
	}

	// Selecting both parent and child is valid.
	t.Run("both selected is valid", func(t *testing.T) {
		selected := map[string]struct{}{parentHash: {}, childHash: {}}
		require.NoError(t, validateDisclosureDependencies(payload, selected, byHash))
	})

	// Selecting only the child (without the parent) is a violation:
	// the verifier can't reach childHash because parentHash is not disclosed.
	t.Run("child without parent is a violation", func(t *testing.T) {
		selected := map[string]struct{}{childHash: {}}
		err := validateDisclosureDependencies(payload, selected, byHash)
		require.Error(t, err)
		require.Contains(t, err.Error(), "disclosure dependency violation")
		require.Contains(t, err.Error(), "child")
	})

	// Selecting only the parent is valid (child is not needed).
	t.Run("parent only is valid", func(t *testing.T) {
		selected := map[string]struct{}{parentHash: {}}
		require.NoError(t, validateDisclosureDependencies(payload, selected, byHash))
	})
}

func TestCreatePresentation_NonSdArray_NotDisclosed(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "tags" is a non-SD array — selecting it yields no disclosures for the array itself.
	// (The SD items inside have no key, so they can't be selected by path.)
	result, err := CreatePresentation(sdJwt, [][]any{{"tags"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.NotContains(t, disclosures, "tags")
}

func TestCreatePresentation_PlaintextArray_NotDisclosed(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "scores" is fully plaintext — no disclosures at all.
	result, err := CreatePresentation(sdJwt, [][]any{{"scores"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_SdArrayAndSdClaim_Combined(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"name"}, {"roles"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "name")
	require.Contains(t, disclosures, "roles")
	require.Len(t, disclosures, 2)
}

func TestCreatePresentation_NestedSdArrayInSdObject(t *testing.T) {
	sdJwt := buildSdJwtWithNestedArrayInObject(t)

	// Select the nested SD array "permissions" inside the SD object "profile".
	result, err := CreatePresentation(sdJwt, [][]any{{"profile", "permissions"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// Both the parent "profile" and nested "permissions" disclosures should be included.
	require.Contains(t, disclosures, "profile")
	require.Contains(t, disclosures, "permissions")
	require.NotContains(t, disclosures, "username")
}

func TestCreatePresentation_NestedSdClaim_AlongsideSdArray(t *testing.T) {
	sdJwt := buildSdJwtWithNestedArrayInObject(t)

	// Select both a scalar SD claim and an SD array from the same parent.
	result, err := CreatePresentation(sdJwt, [][]any{
		{"profile", "username"},
		{"profile", "permissions"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "profile")
	require.Contains(t, disclosures, "username")
	require.Contains(t, disclosures, "permissions")

	// "profile" should appear only once.
	count := 0
	for _, k := range disclosures {
		if k == "profile" {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func buildTestSdJwtWithoutSdAlg(t *testing.T) SdJwtVc {
	t.Helper()
	// Build an SD-JWT without _sd_alg. Per SD-JWT spec Section 4.1.1,
	// the holder MUST default to sha-256 when _sd_alg is absent.
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "TestCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Alice"),
			SdClaim("email", "alice@example.com"),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_MissingSdAlg_DefaultsToSha256(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithoutSdAlg(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.NotContains(t, disclosures, "email")
}

func TestCreatePresentation_MissingSdAlg_AllClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithoutSdAlg(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}, {"email"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "email")
}

// extractDisclosureKeys splits the SD-JWT result and returns the keys of all included disclosures.
func extractDisclosureKeys(t *testing.T, sdJwt SdJwtVc) []string {
	t.Helper()
	_, disclosures, err := splitSdJwtVc(sdJwt)
	require.NoError(t, err)
	var keys []string
	for _, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		require.NoError(t, err)
		keys = append(keys, decoded.Key)
	}
	return keys
}

// extractDecodedDisclosures returns all decoded disclosures from an SD-JWT presentation.
func extractDecodedDisclosures(t *testing.T, sdJwt SdJwtVc) []DisclosureContent {
	t.Helper()
	_, disclosures, err := splitSdJwtVc(sdJwt)
	require.NoError(t, err)
	var result []DisclosureContent
	for _, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		require.NoError(t, err)
		result = append(result, decoded)
	}
	return result
}

// findDisclosure finds the first disclosure with the given key. For array element
// disclosures (empty key), use findArrayElementDisclosures instead.
func findDisclosure(t *testing.T, disclosures []DisclosureContent, key string) DisclosureContent {
	t.Helper()
	for _, d := range disclosures {
		if d.Key == key {
			return d
		}
	}
	t.Fatalf("disclosure with key %q not found", key)
	return DisclosureContent{}
}

// findArrayElementDisclosures returns all disclosures with empty keys (array elements).
func findArrayElementDisclosures(t *testing.T, disclosures []DisclosureContent) []DisclosureContent {
	t.Helper()
	var result []DisclosureContent
	for _, d := range disclosures {
		if d.Key == "" {
			result = append(result, d)
		}
	}
	return result
}
