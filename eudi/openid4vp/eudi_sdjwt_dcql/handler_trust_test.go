package eudi_sdjwt_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
)

// stubIssuerTrust ranks every issuer the same, and remembers which batches it
// was asked about.
type stubIssuerTrust struct {
	level clientmodels.TrustLevel
	meets bool
	asked []string
}

func (s *stubIssuerTrust) IssuerStanding(batch *models.CredentialBatch) (clientmodels.TrustLevel, bool) {
	s.asked = append(s.asked, batch.Hash)
	return s.level, s.meets
}

const trustQuery = `{
	"id": "q1",
	"format": "dc+sd-jwt",
	"meta": {"vct_values": ["https://example.com/EmailCredential"]},
	"claims": [{"path": ["email"]}]
}`

// A credential whose issuer meets the issuance policy is offered, carrying the
// issuer's trust level.
func TestFindCandidates_IssuerTrustLevelIsOnTheCandidate(t *testing.T) {
	h, store := newTestHandler(t)
	trust := &stubIssuerTrust{level: clientmodels.TrustLevel_Medium, meets: true}
	h.issuerTrust = trust
	require.NoError(t, store.StoreBatch(newTestBatch("hash-trusted", "https://example.com/EmailCredential", map[string]any{"email": "a@example.com"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, trustQuery))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	require.Equal(t, clientmodels.TrustLevel_Medium, result.OwnedCandidates[0].Issuer.TrustLevel)
	require.Equal(t, []string{"hash-trusted"}, trust.asked)
}

// A credential whose issuer falls short of the issuance policy in the active
// environment stays in the wallet but is not offered for disclosure.
func TestFindCandidates_IssuerBelowPolicyIsExcluded(t *testing.T) {
	h, store := newTestHandler(t)
	h.issuerTrust = &stubIssuerTrust{level: clientmodels.TrustLevel_Low, meets: false}
	require.NoError(t, store.StoreBatch(newTestBatch("hash-untrusted", "https://example.com/EmailCredential", map[string]any{"email": "a@example.com"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, trustQuery))
	require.NoError(t, err)
	require.Empty(t, result.OwnedCandidates)
}

// Without a trust checker nothing is excluded and nothing is ranked.
func TestFindCandidates_WithoutTrustCheckerIsUnranked(t *testing.T) {
	h, store := newTestHandler(t)
	require.NoError(t, store.StoreBatch(newTestBatch("hash-plain", "https://example.com/EmailCredential", map[string]any{"email": "a@example.com"})))

	result, err := h.FindCandidates(parseDcqlQuery(t, trustQuery))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, result.OwnedCandidates[0].Issuer.TrustLevel)
}
