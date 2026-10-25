package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

// The activity queries run against the snapshot wallets, whose IRMA logs are
// moved from bbolt into the SQL log when the wallet opens. These tests check
// what the queries make of an upgraded wallet; the snapshot regression tests
// check that the entries themselves survived the move.

// allLogPages pages through every entry matching f, a few at a time.
func allLogPages(t *testing.T, c *client.Client, f clientmodels.LogFilter) []clientmodels.LogInfo {
	t.Helper()
	var all []clientmodels.LogInfo
	cursor := ""
	for {
		page, err := c.QueryLogs(clientmodels.LogQuery{Filter: f, Cursor: cursor, Limit: 3})
		require.NoError(t, err)
		all = append(all, page.Entries...)
		if page.NextCursor == "" {
			return all
		}
		require.Len(t, page.Entries, 3, "only the last page may be short")
		cursor = page.NextCursor
	}
}

func TestActivityQueriesOnUpgradedWallet(t *testing.T) {
	c, _, _ := setupStorageRegressionClient(t, "v1.4.0")

	everything, err := c.LoadNewestLogs(1000)
	require.NoError(t, err)

	t.Run("paging returns every entry once, newest first", func(t *testing.T) {
		paged := allLogPages(t, c, clientmodels.LogFilter{IncludeHidden: true})
		require.Len(t, paged, len(everything))
		seen := map[string]bool{}
		for i, e := range paged {
			require.NotEmpty(t, e.ID)
			require.False(t, seen[e.ID], "entry %s returned twice", e.ID)
			seen[e.ID] = true
			if i > 0 {
				require.False(t, paged[i-1].Time.Before(e.Time))
			}
		}
	})

	t.Run("an entry opens by its id", func(t *testing.T) {
		entry, err := c.GetLog(everything[0].ID)
		require.NoError(t, err)
		require.NotNil(t, entry)
		require.Equal(t, everything[0].Type, entry.Type)

		missing, err := c.GetLog("00000000-0000-0000-0000-000000000000")
		require.NoError(t, err)
		require.Nil(t, missing)
	})

	t.Run("type filter and counts", func(t *testing.T) {
		page, err := c.QueryLogs(clientmodels.LogQuery{
			Filter:     clientmodels.LogFilter{Types: []clientmodels.LogType{clientmodels.LogType_CredentialRemoval}, IncludeHidden: true},
			Limit:      1000,
			WithCounts: true,
		})
		require.NoError(t, err)
		require.NotEmpty(t, page.Entries)
		for _, e := range page.Entries {
			require.Equal(t, clientmodels.LogType_CredentialRemoval, e.Type)
		}
		require.Equal(t, len(page.Entries), page.Counts.Total)

		// The counts per type ignore the type filter, so they add up to all.
		sum := 0
		for _, n := range page.Counts.ByType {
			sum += n
		}
		require.Equal(t, len(everything), sum)
		require.Equal(t, countType(everything, clientmodels.LogType_Disclosure), page.Counts.ByType[clientmodels.LogType_Disclosure])
	})

	t.Run("a card's activity", func(t *testing.T) {
		creds, _, err := c.GetCredentials()
		require.NoError(t, err)

		hashes := make([]string, len(creds))
		for i, cred := range creds {
			hashes[i] = cred.Hash
		}
		activity, err := c.CredentialActivity(hashes)
		require.NoError(t, err)
		require.Len(t, activity, len(creds))

		// Every IRMA card was issued in a session that is in the log, and an
		// IRMA issuance names its card exactly.
		for _, cred := range creds {
			if _, idemix := cred.CredentialInstanceIds[clientmodels.Format_Idemix]; !idemix {
				continue
			}
			entries := allLogPages(t, c, clientmodels.LogFilter{CredentialHash: cred.Hash, IncludeHidden: true})
			require.NotEmpty(t, entries, "no activity for %s", cred.CredentialId)
			issued := false
			for _, e := range entries {
				if e.IssuanceLog == nil {
					continue
				}
				for _, ic := range e.IssuanceLog.Credentials {
					if ic.Hash == cred.Hash {
						require.Equal(t, clientmodels.HashConfidence_Exact, ic.HashConfidence)
						issued = true
					}
				}
			}
			require.True(t, issued, "the issuance of %s is not linked to it", cred.CredentialId)
			require.NotNil(t, activity[cred.Hash].LastReceived)
			require.Equal(t, len(entries), activity[cred.Hash].EventCount)
		}
	})

	t.Run("parties", func(t *testing.T) {
		parties, err := c.ListParties(clientmodels.LogFilter{IncludeHidden: true}, 0)
		require.NoError(t, err)
		require.NotEmpty(t, parties)
		for i, p := range parties {
			require.NotEmpty(t, p.Key)
			require.Equal(t, p.Key, p.Party.Id)
			if i > 0 {
				require.False(t, parties[i-1].LastTime.Before(p.LastTime))
			}
			entries := allLogPages(t, c, clientmodels.LogFilter{PartyKey: p.Key, IncludeHidden: true})
			require.Len(t, entries, p.Count)
		}
	})

	t.Run("who has seen an attribute", func(t *testing.T) {
		parties, err := c.ListParties(clientmodels.LogFilter{
			CredentialId: "test.test.email",
			ClaimPath:    []any{"email"},
			Roles:        []clientmodels.LogRole{clientmodels.LogRole_Disclosed},
		}, 0)
		require.NoError(t, err)
		require.NotEmpty(t, parties)
	})

	t.Run("text search ignores case and accents, and searches values", func(t *testing.T) {
		found := allLogPages(t, c, clientmodels.LogFilter{Text: "GMAIL.com", IncludeHidden: true})
		require.NotEmpty(t, found)
		for _, e := range found {
			require.True(t, mentionsValue(e, "test@gmail.com"), "entry %s does not mention the value", e.ID)
		}

		none := allLogPages(t, c, clientmodels.LogFilter{Text: "gmail nosuchword", IncludeHidden: true})
		require.Empty(t, none, "every word must match")

		signed := allLogPages(t, c, clientmodels.LogFilter{Text: "hello world", IncludeHidden: true})
		require.NotEmpty(t, signed)
	})
}

func countType(logs []clientmodels.LogInfo, typ clientmodels.LogType) int {
	n := 0
	for _, l := range logs {
		if l.Type == typ {
			n++
		}
	}
	return n
}

func mentionsValue(e clientmodels.LogInfo, value string) bool {
	for _, c := range logCredentials(e) {
		for _, a := range c.Attributes {
			if a.Value != nil && a.Value.String != nil && *a.Value.String == value {
				return true
			}
		}
	}
	return false
}

// Sessions record the card they were about, so a card's activity is exact
// from the moment it is issued until it is removed.
func TestActivityOfLiveIrmaSessions(t *testing.T) {
	irmaServer := StartIrmaServer(t, IrmaServerConfigurationWithTempStorage(t))
	defer irmaServer.Stop()
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, 1, createIdemixOnlyIssuanceRequest())
	awaitSessionState(t, sessionHandler)
	performIrmaDisclosureSession(t, c, 2, sessionHandler, irmaServer)
	performIrmaSignatureSession(t, c, 3, sessionHandler, irmaServer)

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	var card *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == "test.test.email" {
			card = cred
		}
	}
	require.NotNil(t, card)
	require.NoError(t, c.RemoveCredentialsByHash(card.CredentialInstanceIds))

	entries := allLogPages(t, c, clientmodels.LogFilter{CredentialHash: card.Hash})
	types := []clientmodels.LogType{}
	for _, e := range entries {
		types = append(types, e.Type)
	}
	require.Equal(t, []clientmodels.LogType{
		clientmodels.LogType_CredentialRemoval,
		clientmodels.LogType_Signature,
		clientmodels.LogType_Disclosure,
		clientmodels.LogType_Issuance,
	}, types)
	for _, e := range entries {
		for _, cred := range logCredentials(e) {
			if cred.CredentialId == "test.test.email" {
				require.Equal(t, card.Hash, cred.Hash)
				require.Equal(t, clientmodels.HashConfidence_Exact, cred.HashConfidence)
			}
		}
	}

	activity, err := c.CredentialActivity([]string{card.Hash})
	require.NoError(t, err)
	require.Equal(t, 2, activity[card.Hash].ShareCount, "the disclosure and the signature")
	require.Equal(t, 4, activity[card.Hash].EventCount)

	// Enrolling at the keyshare server issued its credential; the activity
	// log leaves that out unless asked.
	shown := allLogPages(t, c, clientmodels.LogFilter{})
	all := allLogPages(t, c, clientmodels.LogFilter{IncludeHidden: true})
	require.Len(t, all, len(shown)+1)
}

func logCredentials(e clientmodels.LogInfo) []clientmodels.LogCredential {
	switch {
	case e.IssuanceLog != nil:
		return append(append([]clientmodels.LogCredential{}, e.IssuanceLog.Credentials...), e.IssuanceLog.DisclosedCredentials...)
	case e.DisclosureLog != nil:
		return e.DisclosureLog.Credentials
	case e.SignedMessageLog != nil:
		return e.SignedMessageLog.Credentials
	case e.RemovalLog != nil:
		return e.RemovalLog.Credentials
	}
	return nil
}
