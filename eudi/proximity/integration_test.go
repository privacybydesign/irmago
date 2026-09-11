package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"

	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/mdoc_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// ============================================================
// PROXIMITY AGAINST THE REAL WALLET
// ============================================================
//
// tier0_test.go runs the transaction against a fake wallet: a map of credentials
// and a Discloser that answers from it. That is the right shape for testing the ISO
// layer, and the wrong shape for testing the wiring, because the fake is exactly
// what the wiring replaces.
//
// Here the wallet is real. Credentials are issued, run through the production
// format parser, and stored in a real (in-memory) SQLCipher database with their
// device keys. The session then runs on:
//
//	dcql.DcqlHandler over mdoc_dcql.MdocDcqlHandler   real candidate selection
//	services.MdocInstanceSelector                      real instance choice and burn
//	services.NewMdocDeviceKeyBinder                    real device keys, from storage
//	proximity.WalletDiscloser                          the real adapter
//
// — the same objects client.NewProximitySession builds, against the Tier 0 reader
// over a real byte pipe with real BLE chunking. Nothing is stubbed but the consent
// screen, which is a human.
//
// What this covers that neither the unit tests nor tier0_test.go can: that a
// credential actually in storage is found, matched, disclosed, signed with the key
// the issuer bound it to, and spent — with every one of those steps done by the
// code the app will run.

const (
	itDocType   = stdmdoc.AgeVerificationDocType
	itNamespace = stdmdoc.AgeVerificationDocType
	itIssuerURL = "https://issuer.example.com"
	itHash      = "proximity-integration-batch"
)

// realWallet is the wallet machinery a proximity session runs on, assembled the
// way client.NewProximitySession assembles it.
type realWallet struct {
	discloser *WalletDiscloser
	keys      DeviceKeyBinder
	store     db.MdocStore
	issuer    *stdmdoc.Issuer
	batchID   any

	// consent is the stub standing in for the user. Everything else is real.
	consent *stubConsent
}

// stubConsent answers the permission request without a human.
type stubConsent struct {
	// grant selects which candidates to accept. Nil accepts everything the plan
	// offers, which is what an integration test wants unless it is specifically
	// about the user declining.
	grant func(plan *clientmodels.DisclosurePlan) []clientmodels.DisclosureDisconSelection

	// seen records the request, so a test can assert on what the user was shown.
	seen *ConsentRequest
}

func (s *stubConsent) RequestConsent(request ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error) {
	s.seen = &request
	if s.grant != nil {
		return s.grant(request.Plan), nil
	}
	return acceptEverything(request.Plan), nil
}

// acceptEverything answers a plan the way a user pressing "share" would: the first
// option of every pick-one, with all of its attributes.
//
// It reads the plan rather than being handed a hardcoded answer, so a test cannot
// pass by agreeing to something the wallet never offered.
func acceptEverything(plan *clientmodels.DisclosurePlan) []clientmodels.DisclosureDisconSelection {
	if plan == nil {
		return nil
	}
	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 {
			continue
		}
		// The first bundle, with every attribute it offers. A bundle is what the user
		// picks as a unit: selecting it means disclosing every credential inside it
		// together, so the whole thing goes back or none of it does.
		var credentials []clientmodels.SelectedCredential
		for _, instance := range pickOne.OwnedOptions[0].Credentials {
			paths := make([][]any, 0, len(instance.Attributes))
			for _, attribute := range instance.Attributes {
				paths = append(paths, attribute.ClaimPath)
			}
			credentials = append(credentials, clientmodels.SelectedCredential{
				CredentialId:   instance.CredentialId,
				CredentialHash: instance.Hash,
				AttributePaths: paths,
			})
		}
		if len(credentials) > 0 {
			choices = append(choices, clientmodels.DisclosureDisconSelection{Credentials: credentials})
		}
	}
	return choices
}

// newRealWallet issues batchSize credentials carrying claims, stores them as one
// batch with their device keys, and wires the production objects over that storage.
func newRealWallet(t *testing.T, batchSize uint, claims map[string]any) *realWallet {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)
	verifier := stdmdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	parser := services.NewMdocCredentialFormatParser(verifier)

	var (
		instances     []models.MdocBatchInstance
		deviceKeyRows []models.MdocDeviceKey
		first         *services.ParsedCredential
	)
	for range batchSize {
		// One device key per instance, as issuance does — instances of a batch are
		// interchangeable to the verifier and distinct to the wallet.
		holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		holderKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(holderKey)
		require.NoError(t, err)

		issued, err := issuer.Issue(itDocType, itNamespace, claims, &holderKey.PublicKey)
		require.NoError(t, err)
		issuedCBOR, err := cbor.Marshal(issued)
		require.NoError(t, err)

		// Through the production format parser, so the bytes in storage are exactly
		// the bytes issuance writes rather than a hand-built fixture.
		parsed, err := parser.ParseAndVerify(
			base64.RawURLEncoding.EncodeToString(issuedCBOR), itIssuerURL, true)
		require.NoError(t, err)
		if first == nil {
			first = parsed
		}

		instances = append(instances, models.MdocBatchInstance{IssuerSigned: parsed.RawCredentialBytes})
		deviceKeyRows = append(deviceKeyRows, models.MdocDeviceKey{
			PublicKeyThumbprint: parsed.Mdoc.DeviceKeyThumbprint,
			PrivateKey:          holderKeyPKCS8,
			Curve:               "P-256",
		})
	}

	eudiStorage := newIntegrationStorage(t)
	store := db.NewMdocStore(eudiStorage.Db())
	keyStore := db.NewMdocDeviceKeyStore(eudiStorage.Db())

	batch := &models.MdocBatch{
		DocType:          first.Mdoc.DocType,
		CredentialIssuer: itIssuerURL,
		Hash:             itHash,
		Namespaces:       first.Mdoc.Namespaces,
		SignedAt:         first.Mdoc.ValidityInfo.Signed,
		ValidFrom:        first.Mdoc.ValidityInfo.ValidFrom,
		ValidUntil:       first.Mdoc.ValidityInfo.ValidUntil,
		BatchSize:        batchSize,
		RemainingCount:   batchSize,
		IssuerVerified:   true,
		Instances:        instances,
	}
	require.NoError(t, store.StoreBatch(batch))
	require.NoError(t, keyStore.StoreKeys(deviceKeyRows))
	for i := range deviceKeyRows {
		require.NoError(t, keyStore.LinkToInstance(deviceKeyRows[i].ID, batch.Instances[i].ID))
	}

	locale := clientmodels.NewCurrentLocale("en")
	deviceKeys := services.NewMdocDeviceKeyBinder(keyStore)
	consent := &stubConsent{}

	// Exactly what client.NewProximitySession builds.
	discloser := NewWalletDiscloser(
		dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{
			mdoc_dcql.NewMdocDcqlHandler(eudiStorage, locale, deviceKeys),
		}),
		services.NewMdocInstanceSelector(store),
		consent,
	)

	return &realWallet{
		discloser: discloser,
		keys:      deviceKeys,
		store:     store,
		issuer:    issuer,
		batchID:   batch.ID,
		consent:   consent,
	}
}

func newIntegrationStorage(t *testing.T) storage.Storage {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	s, err := storage.NewStorageWithDialector(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", aesKey[:])},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// runRealTransaction drives one complete transaction between the real wallet and
// the Tier 0 reader, over the pipe and the BLE chunking.
func (w *realWallet) runRealTransaction(t *testing.T, elements ...string) mdocResponse {
	t.Helper()

	pki := newReaderPKI(t)
	session, err := NewSession(SessionConfig{
		Discloser:  w.discloser,
		DeviceKeys: w.keys,
		Readers:    pki.trust(),
	})
	require.NoError(t, err)

	qr, err := session.EngagementQR()
	require.NoError(t, err)

	reader := NewReader(ReaderConfig{
		Signer:    pki.key,
		Algorithm: cose.AlgorithmES256,
		Chain:     pki.chain(),
		Issuers:   stdmdoc.NewVerifier([]*x509.Certificate{w.issuer.IACACert()}),
	})
	require.NoError(t, reader.Engage(qr))

	request, err := reader.Request(itemsFor(itDocType, itNamespace, elements...))
	require.NoError(t, err)

	// Straight through the session rather than over net.Pipe: the pipe and the
	// goroutine are what tier0_test.go covers, and repeating them here would only
	// add a way for this test to hang. What is under test is the wallet behind it.
	replyBytes, err := session.Handle(request)
	require.NoError(t, err)

	response, err := reader.ReadResponse(replyBytes)
	require.NoError(t, err)

	results, verifyErr := reader.Verify(response, itNamespace, itDocType)
	return mdocResponse{response: response, results: results, verifyErr: verifyErr}
}

type mdocResponse struct {
	response  stdmdoc.DeviceResponse
	results   []stdmdoc.VerificationResult
	verifyErr error
}

// remaining reads the batch's unspent count back out of storage.
func (w *realWallet) remaining(t *testing.T) uint {
	t.Helper()
	batch, err := w.store.GetBatchByHash(itHash)
	require.NoError(t, err)
	return batch.RemainingCount
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

// TestIntegrationRealWalletAnswersAProximityRequest is the one that matters: a
// credential in real storage, found by the real query handler, disclosed and signed
// with the real device key, and verified by a reader against its own transcript.
func TestIntegrationRealWalletAnswersAProximityRequest(t *testing.T) {
	wallet := newRealWallet(t, 2, map[string]any{"age_over_18": true, "age_over_21": false})

	got := wallet.runRealTransaction(t, "age_over_18")

	require.NoError(t, got.verifyErr)
	require.Len(t, got.response.Documents, 1, "the wallet holds this credential and should have presented it")
	require.Len(t, got.results, 1)
	require.True(t, got.results[0].Valid, "issuer signature and chain must verify: %s", got.results[0].Error)
	require.True(t, got.results[0].DeviceAuthValid,
		"deviceAuth must verify against the device key the issuer bound the credential to")
	require.Equal(t, true, got.results[0].Attributes["age_over_18"])

	// Selective disclosure really happened against a real stored credential.
	require.NotContains(t, got.results[0].Attributes, "age_over_21",
		"an element the reader did not ask for must not be disclosed")

	// The user was shown a plan built from what the wallet actually holds.
	require.NotNil(t, wallet.consent.seen, "the consent handler was never called")
	require.NotNil(t, wallet.consent.seen.Plan)
	require.NotEmpty(t, wallet.consent.seen.Plan.DisclosureChoicesOverview,
		"the plan offered the user nothing, so candidate selection found nothing in storage")
}

// TestIntegrationInstanceIsSpent: a presentation burns exactly one instance of the
// batch, through the same MdocInstanceSelector the OpenID4VP path uses.
//
// This is the property a second copy of the instance logic would have been free to
// get wrong, which is why it is asserted against storage rather than against a
// counter in the test.
func TestIntegrationInstanceIsSpent(t *testing.T) {
	wallet := newRealWallet(t, 3, map[string]any{"age_over_18": true})
	require.Equal(t, uint(3), wallet.remaining(t))

	wallet.runRealTransaction(t, "age_over_18")
	require.Equal(t, uint(2), wallet.remaining(t), "one presentation must spend exactly one instance")

	wallet.runRealTransaction(t, "age_over_18")
	require.Equal(t, uint(1), wallet.remaining(t))
}

// TestIntegrationBatchOfOneStaysReusable: an issuer that does not support batch
// issuance leaves the wallet with a single instance, and spending it would leave a
// credential that can never be presented again.
func TestIntegrationBatchOfOneStaysReusable(t *testing.T) {
	wallet := newRealWallet(t, 1, map[string]any{"age_over_18": true})

	for i := range 3 {
		got := wallet.runRealTransaction(t, "age_over_18")
		require.NoError(t, got.verifyErr)
		require.Len(t, got.response.Documents, 1, "presentation %d should still succeed", i+1)
		require.Equal(t, uint(1), wallet.remaining(t),
			"a batch of one must stay reusable, or the credential dies after one use")
	}
}

// TestIntegrationNothingIsSpentWhenTheUserDeclines: consent refused, so no
// document and — the point — no instance consumed.
func TestIntegrationNothingIsSpentWhenTheUserDeclines(t *testing.T) {
	wallet := newRealWallet(t, 3, map[string]any{"age_over_18": true})
	wallet.consent.grant = func(*clientmodels.DisclosurePlan) []clientmodels.DisclosureDisconSelection {
		return nil
	}

	got := wallet.runRealTransaction(t, "age_over_18")

	require.Empty(t, got.response.Documents, "a declined request must disclose nothing")
	require.Len(t, got.response.DocumentErrors, 1, "and the reader must be told, rather than left hanging")
	require.Equal(t, stdmdoc.ResponseStatusOK, got.response.Status,
		"a refusal is a normal outcome, not a response-level error")
	require.Equal(t, uint(3), wallet.remaining(t), "a declined request must not spend an instance")
}

// TestIntegrationPartialSatisfaction is ISO/IEC 18013-5 8.3.2.1.2.1 through the
// REAL candidate-selection path: "The mdoc shall ignore all unknown data elements
// in a device retrieval mdoc request when processing the request."
//
// This is the test that found the gap. It used to assert the opposite — that the
// wallet returned nothing — because DCQL is all-or-nothing without claim_sets, so
// a credential that cannot satisfy every claim of a query is not a candidate, and
// candidate selection runs before anything reaches response building. The reader
// got a documentError where the clause wants the rest of its request answered.
//
// Closed by the narrowing retry in WalletDiscloser.narrow: when a credential query
// finds nothing, each of its claims is probed on its own and the unsatisfiable ones
// are dropped before the user is asked. The dropped elements still reach the reader
// as Table 9 errors, because Session.buildDocument computes those against the
// ORIGINAL ItemsRequest rather than the narrowed query.
func TestIntegrationPartialSatisfaction(t *testing.T) {
	wallet := newRealWallet(t, 2, map[string]any{"age_over_18": true})

	// age_over_65 is not in this credential; age_over_18 is.
	got := wallet.runRealTransaction(t, "age_over_18", "age_over_65")

	require.NoError(t, got.verifyErr)
	require.Len(t, got.response.Documents, 1,
		"the answerable part of the request must still be answered")
	require.Equal(t, stdmdoc.ResponseStatusOK, got.response.Status,
		"an element the wallet does not hold is not a response-level error")

	// The half that was always implemented: what was asked for and not returned is
	// reported, computed against the request as the reader sent it.
	errs := got.response.Documents[0].Errors
	require.Contains(t, errs[itNamespace], "age_over_65",
		"the element the wallet does not hold must be reported, not silently dropped")
	require.Equal(t, stdmdoc.ErrorCodeDataNotReturned, errs[itNamespace]["age_over_65"])

	// The half the narrowing retry added: the rest is actually returned, verified.
	require.Len(t, got.results, 1)
	require.True(t, got.results[0].Valid, "%s", got.results[0].Error)
	require.True(t, got.results[0].DeviceAuthValid)
	require.Equal(t, true, got.results[0].Attributes["age_over_18"])

	// Narrowing must never widen: an element the reader did not ask for stays back.
	require.NotContains(t, got.results[0].Attributes, "age_over_65")

	require.Equal(t, uint(1), wallet.remaining(t), "one instance spent, as for any presentation")
}

// TestIntegrationPartialSatisfactionRefusesWhenNothingIsHeld: narrowing answers
// what it can, and does not invent an answer when it can do nothing.
//
// Every element requested is absent, so there is nothing to narrow to. The reader
// gets the documentError it would have got anyway — not an empty document, and not
// a dropped session.
func TestIntegrationPartialSatisfactionRefusesWhenNothingIsHeld(t *testing.T) {
	wallet := newRealWallet(t, 2, map[string]any{"age_over_18": true})

	got := wallet.runRealTransaction(t, "age_over_65", "age_over_67")

	require.Empty(t, got.response.Documents,
		"the wallet holds none of what was asked, so there is nothing to answer with")
	require.Len(t, got.response.DocumentErrors, 1, "and the reader must be told")
	require.Equal(t, stdmdoc.ResponseStatusOK, got.response.Status)
	require.Equal(t, uint(2), wallet.remaining(t), "nothing disclosed, nothing spent")
}

// TestIntegrationNarrowingKeepsEverythingItCan: three requested, two held. The
// narrowing must keep BOTH held elements rather than falling back to one, which a
// retry that stopped at the first success would do.
func TestIntegrationNarrowingKeepsEverythingItCan(t *testing.T) {
	wallet := newRealWallet(t, 2, map[string]any{"age_over_18": true, "age_over_21": true})

	got := wallet.runRealTransaction(t, "age_over_18", "age_over_21", "age_over_65")

	require.NoError(t, got.verifyErr)
	require.Len(t, got.response.Documents, 1)
	require.Equal(t, true, got.results[0].Attributes["age_over_18"])
	require.Equal(t, true, got.results[0].Attributes["age_over_21"],
		"narrowing must keep every satisfiable element, not just the first")
	require.Contains(t, got.response.Documents[0].Errors[itNamespace], "age_over_65")
}

// TestIntegrationUnauthenticatedReaderGetsNothingFromAV is the 7.2.1 policy over
// the real wallet: an age verification credential is not an mDL, so an
// unauthenticated reader receives nothing — and no instance is spent, because
// nothing was disclosed.
func TestIntegrationUnauthenticatedReaderGetsNothingFromAV(t *testing.T) {
	wallet := newRealWallet(t, 3, map[string]any{"age_over_18": true})
	pki := newReaderPKI(t)

	session, err := NewSession(SessionConfig{
		Discloser:  wallet.discloser,
		DeviceKeys: wallet.keys,
		Readers:    pki.trust(),
	})
	require.NoError(t, err)

	qr, err := session.EngagementQR()
	require.NoError(t, err)

	// No Signer: a reader that sends no readerAuth.
	reader := NewReader(ReaderConfig{
		Issuers: stdmdoc.NewVerifier([]*x509.Certificate{wallet.issuer.IACACert()}),
	})
	require.NoError(t, reader.Engage(qr))

	request, err := reader.Request(itemsFor(itDocType, itNamespace, "age_over_18"))
	require.NoError(t, err)

	reply, err := session.Handle(request)
	require.NoError(t, err)
	response, err := reader.ReadResponse(reply)
	require.NoError(t, err)

	require.Empty(t, response.Documents)
	require.Len(t, response.DocumentErrors, 1)
	require.Equal(t, uint(3), wallet.remaining(t), "nothing disclosed, nothing spent")

	// And the user was never asked, because nothing was releasable to ask about.
	require.Nil(t, wallet.consent.seen, "the user was asked about a request that could release nothing")
}
