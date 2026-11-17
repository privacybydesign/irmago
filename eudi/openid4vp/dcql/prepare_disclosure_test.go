package dcql

import (
	"context"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/eudi/holdersigning"
	"github.com/stretchr/testify/require"
)

// formatHandler is a credential query handler for one format that needs one
// signature per selection, and presents each selection as the signature it
// got back.
type formatHandler struct {
	format string
}

func (h *formatHandler) CanHandleCredentialQuery(q CredentialQuery) bool { return q.Format == h.format }

func (h *formatHandler) FindCandidates(CredentialQuery) (*CredentialQueryResult, error) {
	return &CredentialQueryResult{}, nil
}

func (h *formatHandler) PrepareDisclosure(selections []DisclosureSelection, _ string, _ string) (*PendingDisclosure, error) {
	pending := &PendingDisclosure{}
	for _, sel := range selections {
		pending.Signatures = append(pending.Signatures, holdersigning.Request{
			Key:   holdersigning.External(h.format),
			Input: []byte(sel.QueryId),
		})
	}
	pending.Complete = func(signatures [][]byte) (*PreparedDisclosure, error) {
		if len(signatures) != len(selections) {
			return nil, fmt.Errorf("%s got %d signatures for %d selections", h.format, len(signatures), len(selections))
		}
		prepared := &PreparedDisclosure{}
		for i, sel := range selections {
			prepared.QueryResponses = append(prepared.QueryResponses, QueryResponse{
				QueryId: sel.QueryId, Credentials: []string{string(signatures[i])},
			})
		}
		return prepared, nil
	}
	return pending, nil
}

// countingSigner signs every input as "<key ref>:<input>" and counts calls.
type countingSigner struct {
	calls int
}

func (s *countingSigner) Sign(_ context.Context, reqs []holdersigning.Request) ([][]byte, error) {
	s.calls++
	sigs := make([][]byte, len(reqs))
	for i, req := range reqs {
		sigs[i] = []byte(req.Key.ExternalRef() + ":" + string(req.Input))
	}
	return sigs, nil
}

// TestPrepareDisclosureSignsEveryFormatInOneCall pins what the two-phase
// PrepareDisclosure is for: a disclosure spanning several formats is signed in
// one call, so a signer that must ask for a PIN asks once, and each format
// gets back exactly its own signatures.
func TestPrepareDisclosureSignsEveryFormatInOneCall(t *testing.T) {
	signer := &countingSigner{}
	h := NewDcqlHandler([]DcqlCredentialQueryHandler{
		&formatHandler{format: "dc+sd-jwt"},
		&formatHandler{format: "mso_mdoc"},
	}, signer)

	query := DcqlQuery{Credentials: []CredentialQuery{
		{Id: "sd1", Format: "dc+sd-jwt"},
		{Id: "md1", Format: "mso_mdoc"},
		{Id: "sd2", Format: "dc+sd-jwt"},
	}}
	prepared, err := h.PrepareDisclosure(context.Background(), query, []DisclosureSelection{
		{QueryId: "sd1"}, {QueryId: "md1"}, {QueryId: "sd2"},
	}, "nonce", "aud", ResponseBinding{})
	require.NoError(t, err)
	require.Equal(t, 1, signer.calls)

	got := map[string]string{}
	for _, r := range prepared.QueryResponses {
		got[r.QueryId] = r.Credentials[0]
	}
	require.Equal(t, map[string]string{
		"sd1": "dc+sd-jwt:sd1",
		"sd2": "dc+sd-jwt:sd2",
		"md1": "mso_mdoc:md1",
	}, got)
}

func TestPrepareDisclosureWithoutSignaturesNeedsNoSigner(t *testing.T) {
	h := NewDcqlHandler([]DcqlCredentialQueryHandler{&noSignatureHandler{}}, nil)
	prepared, err := h.PrepareDisclosure(context.Background(),
		DcqlQuery{Credentials: []CredentialQuery{{Id: "q", Format: "dc+sd-jwt"}}},
		[]DisclosureSelection{{QueryId: "q"}}, "nonce", "aud", ResponseBinding{})
	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
}

type noSignatureHandler struct{ formatHandler }

func (h *noSignatureHandler) CanHandleCredentialQuery(CredentialQuery) bool { return true }

func (h *noSignatureHandler) PrepareDisclosure(selections []DisclosureSelection, _ string, _ string) (*PendingDisclosure, error) {
	return &PendingDisclosure{Complete: func([][]byte) (*PreparedDisclosure, error) {
		return &PreparedDisclosure{QueryResponses: []QueryResponse{{QueryId: selections[0].QueryId}}}, nil
	}}, nil
}
