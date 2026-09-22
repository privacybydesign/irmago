package integrationtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
)

// ============================================================
// 1. THE HAPPY PATH
// ============================================================

// TestReaderReceivesASignedDocument is the whole exchange with nothing faked but
// the user: a reader authenticates, asks for one element, the wallet finds a
// genuinely issued credential in real storage, and the reader opens the sealed
// answer and verifies it.
//
// The device signature check is the load-bearing assertion. It passes only if
// the wallet and the reader derived the same session transcript from the same
// encryptionInfo text and origin, the stored instance was stripped without
// disturbing its issuer signature, and the device key resolved from the MSO was
// the one the credential is actually bound to. Nothing below the composition can
// establish that on its own.
func TestReaderReceivesASignedDocument(t *testing.T) {
	env := newEnv(t, 1)

	sealed, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
	require.NoError(t, err)

	// The reader was authenticated, which for an AV credential is the difference
	// between this test and a refusal — see TestUnauthenticatedReaderGetsNothing.
	require.True(t, env.consent.called, "the user must have been asked")
	require.Equal(t, testOrigin, env.consent.seen.Origin)
	require.Len(t, env.consent.seen.Documents, 1)
	require.True(t, env.consent.seen.Documents[0].Authenticated(),
		"the readerAuth was signed by a certificate chaining to the wallet's anchor")
	require.Equal(t, "Test mdoc Reader", env.consent.seen.Documents[0].Reader.CommonName())

	response := env.reader.open(t, sealed)
	require.Equal(t, mdoc.DeviceResponseVersion, response.Version)
	require.Equal(t, mdoc.ResponseStatusOK, response.Status)
	require.Empty(t, response.DocumentErrors)
	require.Len(t, response.Documents, 1)

	document := response.Documents[0]
	require.NotNil(t, document.DeviceSigned, "the document must be signed for this session")
	require.NotEmpty(t, document.DeviceSigned.DeviceAuth.DeviceSignature)
	require.Empty(t, document.DeviceSigned.DeviceAuth.DeviceMac, "this wallet signs, never MACs")
	require.Empty(t, document.Errors, "everything asked for was returned")

	// Only what was consented to. The credential also holds age_over_16 and
	// age_over_21; neither was asked for, so neither may travel.
	disclosed, err := document.DisclosedElements()
	require.NoError(t, err)
	require.Equal(t, []string{"age_over_18"}, disclosed[avNameSpace])

	results, err := env.issuerVerifier.VerifyDeviceResponse(
		response, avNameSpace, avDocType, env.reader.transcript(t))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Valid, "issuer verification failed: %s", results[0].Error)
	require.True(t, results[0].DeviceAuthValid, "deviceAuth did not verify: %s", results[0].Error)
	require.Equal(t, map[string]any{"age_over_18": true}, results[0].Attributes)
}

// ============================================================
// 2. PARTIAL SATISFACTION — ISO/IEC 18013-5 8.3.2.1.2.1
// ============================================================

// TestPartialSatisfactionEndToEnd asks for one element the wallet holds and one
// it does not, and requires the held one back with the other reported.
//
// This is the single most valuable assertion in the package, because it is the
// one the layer tests structurally cannot make. DCQL is all-or-nothing: a
// credential query naming an element the wallet does not hold matches no
// candidate at all. So answering this request means the real candidate search
// has to come back empty, WalletDiscloser.narrow has to probe each claim through
// that same search, the retry has to find the credential, and signDocument has
// to compute its errors against the ORIGINAL request rather than the narrowed
// one. Every one of those steps crosses a seam, and a gap in exactly this
// machinery once survived review because a fake wallet never ran a real query.
func TestPartialSatisfactionEndToEnd(t *testing.T) {
	env := newEnv(t, 1)

	sealed, err := env.respond(t,
		env.reader.request(t, true, avDocType, avNameSpace, "age_over_18", "age_over_65"))
	require.NoError(t, err)

	// The narrowing reached the user, not just the response: the consent screen
	// must not offer an element the wallet cannot produce.
	require.Len(t, env.consent.seen.Query.Credentials, 1)
	require.Len(t, env.consent.seen.Query.Credentials[0].Claims, 1,
		"age_over_65 is not held, so it must have been narrowed out before consent")
	require.Equal(t, []any{avNameSpace, "age_over_18"},
		env.consent.seen.Query.Credentials[0].Claims[0].Path)

	response := env.reader.open(t, sealed)
	require.Len(t, response.Documents, 1)
	require.Empty(t, response.DocumentErrors,
		"the document WAS returned, so this is an element-level failure, not a document-level one")

	document := response.Documents[0]
	disclosed, err := document.DisclosedElements()
	require.NoError(t, err)
	require.Equal(t, []string{"age_over_18"}, disclosed[avNameSpace],
		"the held element must be answered rather than the whole request refused")

	require.NotNil(t, document.Errors,
		"an element asked for and not returned is reported, not silently dropped")
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, document.Errors[avNameSpace]["age_over_65"])
	require.NotContains(t, document.Errors[avNameSpace], "age_over_18",
		"what was returned is not an error")

	// A narrowed answer is still a genuine presentation, not a best-effort one.
	results, err := env.issuerVerifier.VerifyDeviceResponse(
		response, avNameSpace, avDocType, env.reader.transcript(t))
	require.NoError(t, err)
	require.True(t, results[0].Valid, "issuer verification failed: %s", results[0].Error)
	require.True(t, results[0].DeviceAuthValid, "deviceAuth did not verify: %s", results[0].Error)
	require.Equal(t, map[string]any{"age_over_18": true}, results[0].Attributes)
}

// ============================================================
// 3. REFUSAL
// ============================================================

// TestRefusalIsAWellFormedEmptyResponse: the user declines, and the reader gets
// a sealed, status-0 response naming every document it asked for and did not
// get. A non-zero status would claim the request could not be PROCESSED
// (8.3.2.1.2.3), which is not what happened when somebody simply said no.
func TestRefusalIsAWellFormedEmptyResponse(t *testing.T) {
	env := newEnv(t, 2)
	env.consent.refuse = true

	sealed, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
	require.NoError(t, err, "a refusal is a successful exchange in which nothing was agreed")

	response := env.reader.open(t, sealed)
	require.Empty(t, response.Documents)
	require.Equal(t, mdoc.ResponseStatusOK, response.Status)
	require.Len(t, response.DocumentErrors, 1)
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, response.DocumentErrors[0][avDocType])

	require.Equal(t, uint(2), env.remaining(t),
		"a declined request must not cost the holder a single-use instance")
}

// TestUnauthenticatedReaderGetsNothing is ISO/IEC 18013-5 7.2.1 reached through
// the whole stack: the AV profile has no mandatory-element carve-out, so a
// reader that sends no readerAuth is entitled to nothing.
//
// Written out rather than left implicit because it is the shape of an
// integration test that looks broken and is not: no consent screen appears, the
// response carries no documents, and every one of those is correct.
func TestUnauthenticatedReaderGetsNothing(t *testing.T) {
	env := newEnv(t, 2)

	sealed, err := env.respond(t, env.reader.request(t, false, avDocType, avNameSpace, "age_over_18"))
	require.NoError(t, err)

	require.False(t, env.consent.called,
		"a request that can only be refused must not put a question to the user")

	response := env.reader.open(t, sealed)
	require.Empty(t, response.Documents)
	require.Len(t, response.DocumentErrors, 1)
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, response.DocumentErrors[0][avDocType])
	require.Equal(t, uint(2), env.remaining(t))
}

// ============================================================
// 4. INSTANCE ACCOUNTING
// ============================================================

// TestInstanceAccounting covers the reserve/spend split against real rows: an
// instance is spent only once a response exists, a failure gives it back, and a
// batch of one is never spent at all.
func TestInstanceAccounting(t *testing.T) {
	t.Run("an instance is spent once the response is sealed", func(t *testing.T) {
		env := newEnv(t, 2)
		require.Equal(t, uint(2), env.remaining(t))

		// Nothing is spent while the user is still deciding.
		env.consent.before = func(isomdoc.ConsentRequest) {
			require.Equal(t, uint(2), env.remaining(t),
				"the user has not answered yet, so nothing can have been spent")
		}

		_, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err)
		require.Equal(t, uint(1), env.remaining(t))
	})

	t.Run("a failure after reserving spends nothing", func(t *testing.T) {
		env := newEnv(t, 2)
		binder := &failFirstBinder{inner: env.realBinder(), failures: 1}
		env.wire(binder)

		_, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.ErrorContains(t, err, "injected fault",
			"the fault must land after the instance was reserved, not before")
		require.Equal(t, uint(2), env.remaining(t),
			"an instance may not be spent on a response that was never built")

		// And the wallet is not poisoned: the very next request succeeds.
		_, err = env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err)
		require.Equal(t, uint(1), env.remaining(t))
	})

	t.Run("a failure gives the only instance back", func(t *testing.T) {
		// A batch of one is the sharp case for the release path: the instance the
		// failed disclosure reserved is the only one there is, so if it stayed
		// claimed the retry would find nothing rather than merely picking a
		// different copy.
		env := newEnv(t, 1)
		env.wire(&failFirstBinder{inner: env.realBinder(), failures: 1})

		_, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.ErrorContains(t, err, "injected fault")

		env.wire(env.realBinder())
		sealed, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err, "the instance the failed disclosure held must be available again")
		require.Len(t, env.reader.open(t, sealed).Documents, 1)
	})

	t.Run("a batch of one stays reusable", func(t *testing.T) {
		// An issuer without batch issuance yields BatchSize 1, and spending that
		// single instance would leave the wallet holding a credential it can never
		// present again. MdocInstanceSelector.Spend short-circuits for exactly this.
		env := newEnv(t, 1)

		for attempt := range 2 {
			sealed, err := env.respond(t,
				env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
			require.NoError(t, err, "presentation %d", attempt)

			results, err := env.issuerVerifier.VerifyDeviceResponse(
				env.reader.open(t, sealed), avNameSpace, avDocType, env.reader.transcript(t))
			require.NoError(t, err)
			require.True(t, results[0].DeviceAuthValid, "deviceAuth did not verify: %s", results[0].Error)
			require.Equal(t, uint(1), env.remaining(t))
		}
	})
}
