package mdocpresent

import (
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// These exercise the wallet side: the query built from what 7.2.1 permits, the
// narrowing retry of 8.3.2.1.2.1, and the reserve/strip/sign-key composition.
//
// The DCQL handler under test is a fake, and deliberately so. The real mso_mdoc
// one needs SQLCipher, which needs cgo, which does not build on every machine
// this package is developed on; and what is under test here is not whether that
// handler matches claims correctly — it has its own round-trip test for that —
// but what this file does with the answer. The instance selector, the stripping
// and the claim-path reading are the real ones.

// ============================================================
// FAKES
// ============================================================

// heldCredential is what the fake wallet holds: one batch of one docType.
type heldCredential struct {
	docType   string
	namespace string
	hash      string
	elements  map[string]any
}

// fakeQueryHandler answers DCQL queries out of heldCredential, all-or-nothing the
// way the real mso_mdoc handler does: a credential query naming an element the
// wallet does not hold yields no candidate at all. That behaviour is the entire
// reason narrow exists, so a fake that was lenient about it would test nothing.
type fakeQueryHandler struct {
	held  heldCredential
	calls int
}

func (f *fakeQueryHandler) CanHandleCredentialQuery(query dcql.CredentialQuery) bool {
	return query.Format == string(clientmodels.Format_MsoMdoc)
}

func (f *fakeQueryHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	f.calls++
	result := &dcql.CredentialQueryResult{}

	if query.Meta == nil || query.Meta.DocTypeValue != f.held.docType {
		return result, nil
	}
	if len(query.Claims) == 0 {
		return nil, fmt.Errorf("credential query %q requests no claims", query.Id)
	}

	attributes := make([]clientmodels.Attribute, 0, len(query.Claims))
	for _, claim := range query.Claims {
		if len(claim.Path) != 2 {
			return nil, fmt.Errorf("credential query %q: mso_mdoc claim paths are [namespace, element]", query.Id)
		}
		namespace, _ := claim.Path[0].(string)
		element, _ := claim.Path[1].(string)
		if namespace != f.held.namespace {
			return result, nil
		}
		if _, ok := f.held.elements[element]; !ok {
			return result, nil // all-or-nothing
		}
		attributes = append(attributes, clientmodels.Attribute{ClaimPath: claim.Path})
	}

	result.OwnedCandidates = append(result.OwnedCandidates, &clientmodels.SelectableCredentialInstance{
		CredentialId: f.held.docType,
		Hash:         f.held.hash,
		Name:         f.held.docType,
		Format:       clientmodels.Format_MsoMdoc,
		Attributes:   attributes,
	})
	return result, nil
}

func (f *fakeQueryHandler) PrepareDisclosure([]dcql.DisclosureSelection, string, string) (*dcql.PreparedDisclosure, error) {
	return nil, fmt.Errorf("the org-iso-mdoc path does not prepare disclosures through the DCQL handler")
}

// fakeStore is the slice of db.MdocStore an instance selector actually uses.
type fakeStore struct {
	db.MdocStore

	batch     *models.MdocBatch
	instances []*models.MdocBatchInstance
	used      map[datatypes.UUID]bool
}

func (s *fakeStore) GetBatchByHash(hash string) (*models.MdocBatch, error) {
	if s.batch == nil || s.batch.Hash != hash {
		return nil, fmt.Errorf("no batch with hash %s", hash)
	}
	return s.batch, nil
}

func (s *fakeStore) GetUnusedInstanceExcluding(
	batchID datatypes.UUID,
	excluded []datatypes.UUID,
) (*models.MdocBatchInstance, error) {
	skip := make(map[datatypes.UUID]struct{}, len(excluded))
	for _, id := range excluded {
		skip[id] = struct{}{}
	}
	for _, instance := range s.instances {
		if s.used[instance.ID] {
			continue
		}
		if _, ok := skip[instance.ID]; ok {
			continue
		}
		return instance, nil
	}
	return nil, fmt.Errorf("no unused instance for batch %s", batchID)
}

func (s *fakeStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	if s.used == nil {
		s.used = map[datatypes.UUID]bool{}
	}
	s.used[instanceID] = true
	return nil
}

// fakeBinder hands back the holder the test issued the credential to, or fails
// when the test wants to see what a missing device key does.
type fakeBinder struct {
	holder mdoc.Holder
	err    error
}

func (b fakeBinder) HolderForDeviceKey(*ecdsa.PublicKey) (mdoc.Holder, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.holder, nil
}

// fakeConsent approves everything the plan offers, or refuses, and records what
// it was shown.
type fakeConsent struct {
	refuse bool
	err    error
	seen   ConsentRequest
	called bool
}

func (c *fakeConsent) RequestConsent(request ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error) {
	c.called = true
	c.seen = request
	if c.err != nil {
		return nil, c.err
	}
	if c.refuse {
		return nil, nil
	}

	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range request.Plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 {
			continue
		}
		var selected []clientmodels.SelectedCredential
		for _, credential := range pickOne.OwnedOptions[0].Credentials {
			paths := make([][]any, 0, len(credential.Attributes))
			for _, attribute := range credential.Attributes {
				paths = append(paths, attribute.ClaimPath)
			}
			selected = append(selected, clientmodels.SelectedCredential{
				CredentialId:   credential.CredentialId,
				CredentialHash: credential.Hash,
				AttributePaths: paths,
			})
		}
		choices = append(choices, clientmodels.DisclosureDisconSelection{Credentials: selected})
	}
	return choices, nil
}

// ============================================================
// THE WALLET UNDER TEST
// ============================================================

type walletEnv struct {
	discloser *WalletDiscloser
	queries   *fakeQueryHandler
	store     *fakeStore
	consent   *fakeConsent
	holder    mdoc.Holder
	hash      string
}

// newWalletEnv issues a real mdoc, stores it as a batch of two instances, and
// wires a discloser over it.
func newWalletEnv(t *testing.T, claims map[string]any) *walletEnv {
	t.Helper()

	document, holder := credential(t, avDocType, avNameSpace, claims)
	stored, err := cbor.Marshal(mdoc.MDoc{DocType: document.DocType, IssuerSigned: document.IssuerSigned})
	require.NoError(t, err)

	batchID := datatypes.NewUUIDv4()
	batch := &models.MdocBatch{
		ID:             batchID,
		DocType:        avDocType,
		Hash:           "credential-hash",
		BatchSize:      2,
		RemainingCount: 2,
	}
	instances := []*models.MdocBatchInstance{
		{ID: datatypes.NewUUIDv4(), MdocBatchID: batchID, IssuerSigned: stored},
		{ID: datatypes.NewUUIDv4(), MdocBatchID: batchID, IssuerSigned: stored},
	}

	elements := make(map[string]any, len(claims))
	for name, value := range claims {
		elements[name] = value
	}

	queries := &fakeQueryHandler{held: heldCredential{
		docType:   avDocType,
		namespace: avNameSpace,
		hash:      batch.Hash,
		elements:  elements,
	}}
	store := &fakeStore{batch: batch, instances: instances, used: map[datatypes.UUID]bool{}}
	consent := &fakeConsent{}

	return &walletEnv{
		discloser: NewWalletDiscloser(
			dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{queries}),
			services.NewMdocInstanceSelector(store),
			fakeBinder{holder: holder},
			consent,
		),
		queries: queries,
		store:   store,
		consent: consent,
		holder:  holder,
		hash:    batch.Hash,
	}
}

// requestFor builds the evaluated documents a session would hand the wallet: an
// authenticated reader asking for the named elements.
func requestFor(elements ...string) DisclosureRequest {
	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}
	items := mdoc.ItemsRequest{
		DocType:    avDocType,
		NameSpaces: map[string]mdoc.DataElements{avNameSpace: wanted},
	}
	return DisclosureRequest{
		Origin: testOrigin,
		Documents: []RequestedDocument{{
			DocType:   avDocType,
			Requested: items,
			Permitted: items,
			Reader:    &mdoc.ReaderAuthResult{},
		}},
	}
}

// TestWalletDiscloserDisclosesWhatWasConsentedTo is the happy path: one
// credential, one element consented to, one selection carrying the stripped
// document and a holder that can sign it.
func TestWalletDiscloserDisclosesWhatWasConsentedTo(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true, "age_over_21": true})

	selections, err := env.discloser.Disclose(requestFor("age_over_18"))
	require.NoError(t, err)
	require.Len(t, selections, 1)

	selection := selections[0]
	require.Equal(t, avDocType, selection.DocType)
	require.Equal(t, avDocType, selection.Document.DocType,
		"the label and the document must agree, or deviceAuth signs a docType the document does not carry")
	require.NotNil(t, selection.Holder)

	disclosed, err := selection.Document.DisclosedElements()
	require.NoError(t, err)
	require.Equal(t, []string{"age_over_18"}, disclosed[avNameSpace],
		"age_over_21 was held but not asked for, so it must not be in the document")

	require.Nil(t, selection.Document.DeviceSigned,
		"the discloser must not sign: assemble owns the session transcript")
}

// TestWalletDiscloserBuildsQueryFromPermitted is the 7.2.1 boundary. An
// unauthenticated reader asks for two elements and is entitled to one; the query
// the wallet plans from, and therefore the consent screen and the disclosure, must
// carry only that one.
func TestWalletDiscloserBuildsQueryFromPermitted(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true, "portrait": "…"})

	request := requestFor("age_over_18", "portrait")
	request.Documents[0].Reader = nil // unauthenticated
	request.Documents[0].Permitted = mdoc.ItemsRequest{
		DocType:    avDocType,
		NameSpaces: map[string]mdoc.DataElements{avNameSpace: {"age_over_18": false}},
	}
	request.Documents[0].Withheld = map[string][]string{avNameSpace: {"portrait"}}

	selections, err := env.discloser.Disclose(request)
	require.NoError(t, err)
	require.Len(t, selections, 1)

	require.True(t, env.consent.called)
	require.Len(t, env.consent.seen.Query.Credentials, 1)
	require.Len(t, env.consent.seen.Query.Credentials[0].Claims, 1,
		"the withheld element must not reach the query, the consent screen or the log")
	require.Equal(t, []any{avNameSpace, "age_over_18"}, env.consent.seen.Query.Credentials[0].Claims[0].Path)

	disclosed, err := selections[0].Document.DisclosedElements()
	require.NoError(t, err)
	require.Equal(t, []string{"age_over_18"}, disclosed[avNameSpace])
}

// TestWalletDiscloserRefusesWhenNothingIsServable: an unauthenticated reader
// asking only for elements 7.2.1 withholds gets no consent screen and no
// selections. The reader learns of it through documentErrors, which is the
// session's job.
func TestWalletDiscloserRefusesWhenNothingIsServable(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"portrait": "…"})

	request := requestFor("portrait")
	request.Documents[0].Reader = nil
	request.Documents[0].Permitted = mdoc.ItemsRequest{DocType: avDocType}
	request.Documents[0].Withheld = map[string][]string{avNameSpace: {"portrait"}}

	selections, err := env.discloser.Disclose(request)
	require.NoError(t, err, "a refusal is not a failure")
	require.Empty(t, selections)
	require.False(t, env.consent.called, "there is nothing to ask the user about")
}

// TestWalletDiscloserNarrowsUnknownElements is ISO/IEC 18013-5 8.3.2.1.2.1: a
// reader asking for one element the wallet does not hold must still get the ones
// it does, rather than nothing at all because DCQL is all-or-nothing.
func TestWalletDiscloserNarrowsUnknownElements(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true})

	selections, err := env.discloser.Disclose(requestFor("age_over_18", "age_over_65"))
	require.NoError(t, err)
	require.Len(t, selections, 1, "the held element must still be disclosed")

	disclosed, err := selections[0].Document.DisclosedElements()
	require.NoError(t, err)
	require.Equal(t, []string{"age_over_18"}, disclosed[avNameSpace])

	require.Len(t, env.consent.seen.Query.Credentials[0].Claims, 1,
		"the unheld element is dropped from the query, not disclosed as empty")
}

// TestWalletDiscloserDoesNotNarrowASingleClaim: one claim narrowed to nothing is
// just a refusal, so the query is left as the reader wrote it and no probes run.
func TestWalletDiscloserDoesNotNarrowASingleClaim(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true})

	selections, err := env.discloser.Disclose(requestFor("age_over_65"))
	require.NoError(t, err)
	require.Empty(t, selections)
	require.Equal(t, 1, env.queries.calls, "a single-claim query must not be probed")
}

// TestWalletDiscloserDoesNotNarrowWhenEverythingIsHeld: narrowing must not fire on
// a request the wallet can answer as asked, which is the common case and the one
// that would pay for the probes.
func TestWalletDiscloserDoesNotNarrowWhenEverythingIsHeld(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true, "age_over_21": true})

	_, err := env.discloser.Disclose(requestFor("age_over_18", "age_over_21"))
	require.NoError(t, err)
	require.Equal(t, 1, env.queries.calls, "an answerable request must cost exactly one search")
}

// TestWalletDiscloserRefusalIsNotAFailure: the user declining produces no
// selections and no error, which the session turns into documentErrors.
func TestWalletDiscloserRefusalIsNotAFailure(t *testing.T) {
	env := newWalletEnv(t, map[string]any{"age_over_18": true})
	env.consent.refuse = true

	selections, err := env.discloser.Disclose(requestFor("age_over_18"))
	require.NoError(t, err)
	require.Empty(t, selections)
}

// TestWalletDiscloserSpendsOnlyOnCommit is the single-use accounting: reserving
// must not consume anything, and an abandoned disclosure must give its instance
// back rather than strand it.
func TestWalletDiscloserSpendsOnlyOnCommit(t *testing.T) {
	t.Run("commit spends", func(t *testing.T) {
		env := newWalletEnv(t, map[string]any{"age_over_18": true})

		_, err := env.discloser.Disclose(requestFor("age_over_18"))
		require.NoError(t, err)
		require.Empty(t, env.store.used, "reserving must not consume an instance")

		require.NoError(t, env.discloser.Commit())
		require.Len(t, env.store.used, 1)

		// A second disclosure gets the other instance, not the spent one.
		second, err := env.discloser.Disclose(requestFor("age_over_18"))
		require.NoError(t, err)
		require.Len(t, second, 1)
		require.NoError(t, env.discloser.Commit())
		require.Len(t, env.store.used, 2)
	})

	t.Run("release frees the reservation", func(t *testing.T) {
		env := newWalletEnv(t, map[string]any{"age_over_18": true})

		_, err := env.discloser.Disclose(requestFor("age_over_18"))
		require.NoError(t, err)
		env.discloser.Release()
		require.Empty(t, env.store.used)

		// Released, so the same instance is available again: two disclosures in a
		// row on a batch of two must not exhaust it.
		for range 2 {
			_, err := env.discloser.Disclose(requestFor("age_over_18"))
			require.NoError(t, err)
			env.discloser.Release()
		}
	})

	t.Run("a failure after reserving releases", func(t *testing.T) {
		env := newWalletEnv(t, map[string]any{"age_over_18": true})
		env.discloser.deviceKeys = fakeBinder{err: fmt.Errorf("device key lives in hardware that said no")}

		_, err := env.discloser.Disclose(requestFor("age_over_18"))
		require.Error(t, err)
		require.Empty(t, env.store.used)

		// Nothing is stranded: the next disclosure still finds an instance.
		env.discloser.deviceKeys = fakeBinder{holder: env.holder}
		selections, err := env.discloser.Disclose(requestFor("age_over_18"))
		require.NoError(t, err)
		require.Len(t, selections, 1)
	})
}

// TestWalletDiscloserNeedsItsCollaborators: a half-wired discloser must say so
// rather than nil-dereference partway through a disclosure.
func TestWalletDiscloserNeedsItsCollaborators(t *testing.T) {
	_, err := (&WalletDiscloser{}).Disclose(requestFor("age_over_18"))
	require.ErrorContains(t, err, "missing its query handler")
}
