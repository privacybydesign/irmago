package myirmaserver

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/privacybydesign/irmago/irma/server/keyshare"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	linkUsername = "testuser"
	linkEmail    = "test@example.com"
	linkUserID   = 15
)

func newLinkTestDB() *memoryDB {
	return &memoryDB{
		userData: map[string]memoryUserData{
			linkUsername: {id: linkUserID, lastActive: time.Unix(0, 0)},
		},
	}
}

func linkResult(username, email string) *server.SessionResult {
	return &server.SessionResult{
		Status:      irma.ServerStatusDone,
		ProofStatus: irma.ProofStatusValid,
		Disclosed: [][]*irma.DisclosedAttribute{
			{{RawValue: &username}},
			{{RawValue: &email}},
		},
	}
}

func linkedEmails(t *testing.T, db *memoryDB) []userEmail {
	user, err := db.user(context.Background(), linkUserID)
	require.NoError(t, err)
	return user.Emails
}

// restartLinkWatchers undoes the Stop call of StartMyIrmaServer for the goroutines
// that wait for link sessions.
func restartLinkWatchers(s *Server) {
	s.stopCtx, s.stopLinks = context.WithCancel(context.Background())
	s.linkPollInterval = 10 * time.Millisecond
}

func TestNewIrmaDisclosureRequest(t *testing.T) {
	keyshareAttr := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	otherKeyshareAttr := irma.NewAttributeTypeIdentifier("test2.test.mijnirma.email")
	emailAttr := irma.NewAttributeTypeIdentifier("test.test.email.email")

	single := newIrmaDisclosureRequest([]irma.AttributeTypeIdentifier{keyshareAttr, otherKeyshareAttr})
	require.Len(t, single.Disclose, 1)
	assert.Len(t, single.Disclose[0], 2)

	both := newIrmaDisclosureRequest(
		[]irma.AttributeTypeIdentifier{keyshareAttr, otherKeyshareAttr},
		[]irma.AttributeTypeIdentifier{emailAttr},
	)
	require.Len(t, both.Disclose, 2)
	assert.Equal(t, irma.AttributeDisCon{
		irma.AttributeCon{irma.NewAttributeRequest(keyshareAttr.String())},
		irma.AttributeCon{irma.NewAttributeRequest(otherKeyshareAttr.String())},
	}, both.Disclose[0])
	assert.Equal(t, irma.AttributeDisCon{
		irma.AttributeCon{irma.NewAttributeRequest(emailAttr.String())},
	}, both.Disclose[1])
}

func TestServerLinkEmailStartsSession(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newLinkTestDB(), "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	// No login is involved and no session cookie is set.
	client := test.NewHTTPClient()
	var pkg server.SessionPackage
	test.HTTPPost(t, client, "http://localhost:8081/email/link", "", nil, 200, &pkg)

	require.NotNil(t, pkg.SessionPtr)
	assert.Equal(t, irma.ActionDisclosing, pkg.SessionPtr.Type)
	assert.NotEmpty(t, pkg.SessionPtr.URL)
	require.NotNil(t, pkg.FrontendRequest)
	assert.NotEmpty(t, pkg.FrontendRequest.Authorization)
	assert.Empty(t, client.Jar.Cookies(&url.URL{Scheme: "http", Host: "localhost:8081"}))
}

func TestServerLinkEmailPendingLimit(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newLinkTestDB(), "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	for range cap(myirmaServer.linkSlots) {
		myirmaServer.linkSlots <- struct{}{}
	}

	test.HTTPPost(t, nil, "http://localhost:8081/email/link", "", nil, 429, nil)
}

func TestServerLinkEmailReleasesSlot(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newLinkTestDB(), "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)
	restartLinkWatchers(myirmaServer)

	// Until the session is finished the watcher keeps its slot.
	_, token, _, err := myirmaServer.irmaserv.StartSession(
		newIrmaDisclosureRequest(myirmaServer.conf.KeyshareAttributes, myirmaServer.conf.EmailAttributes),
		nil, "",
	)
	require.NoError(t, err)
	myirmaServer.linkSlots <- struct{}{}
	go myirmaServer.awaitLinkEmail(token)
	time.Sleep(10 * myirmaServer.linkPollInterval)
	assert.Len(t, myirmaServer.linkSlots, 1)

	require.NoError(t, myirmaServer.irmaserv.CancelSession(token))
	require.Eventually(t, func() bool { return len(myirmaServer.linkSlots) == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestServerLinkEmailStopEndsWatchers(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newLinkTestDB(), "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)
	restartLinkWatchers(myirmaServer)

	test.HTTPPost(t, nil, "http://localhost:8081/email/link", "", nil, 200, nil)
	require.Len(t, myirmaServer.linkSlots, 1)

	myirmaServer.Stop()
	require.Eventually(t, func() bool { return len(myirmaServer.linkSlots) == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestProcessLinkEmailResult(t *testing.T) {
	ctx := context.Background()
	nilValue := func(result *server.SessionResult) *server.SessionResult {
		result.Disclosed[1][0].RawValue = nil
		return result
	}
	withStatus := func(result *server.SessionResult, status irma.ServerStatus) *server.SessionResult {
		result.Status = status
		return result
	}
	invalidProofs := linkResult(linkUsername, linkEmail)
	invalidProofs.ProofStatus = irma.ProofStatusInvalid
	oneAttribute := linkResult(linkUsername, linkEmail)
	oneAttribute.Disclosed = oneAttribute.Disclosed[:1]

	t.Run("links email to the user of the disclosed username", func(t *testing.T) {
		db := newLinkTestDB()
		s := &Server{db: db}

		require.NoError(t, s.processLinkEmailResult(ctx, linkResult(linkUsername, linkEmail)))
		assert.Equal(t, []userEmail{{Email: linkEmail}}, linkedEmails(t, db))
	})

	t.Run("an already linked email stays linked once", func(t *testing.T) {
		db := newLinkTestDB()
		s := &Server{db: db}

		require.NoError(t, s.processLinkEmailResult(ctx, linkResult(linkUsername, linkEmail)))
		require.NoError(t, s.processLinkEmailResult(ctx, linkResult(linkUsername, linkEmail)))
		assert.Equal(t, []userEmail{{Email: linkEmail}}, linkedEmails(t, db))
	})

	t.Run("unknown username", func(t *testing.T) {
		db := newLinkTestDB()
		s := &Server{db: db}

		assert.Equal(t, keyshare.ErrUserNotFound, s.processLinkEmailResult(ctx, linkResult("unknown", linkEmail)))
		assert.Empty(t, linkedEmails(t, db))
	})

	for name, result := range map[string]*server.SessionResult{
		"invalid proofs":       invalidProofs,
		"one disclosed value":  oneAttribute,
		"missing email value":  nilValue(linkResult(linkUsername, linkEmail)),
		"no disclosed values":  {Status: irma.ServerStatusDone, ProofStatus: irma.ProofStatusValid},
		"empty disclosed list": {Status: irma.ServerStatusDone, ProofStatus: irma.ProofStatusValid, Disclosed: [][]*irma.DisclosedAttribute{{}, {}}},
	} {
		t.Run(name, func(t *testing.T) {
			db := newLinkTestDB()
			s := &Server{db: db}

			assert.Error(t, s.processLinkEmailResult(ctx, result))
			assert.Empty(t, linkedEmails(t, db))
		})
	}

	for _, status := range []irma.ServerStatus{irma.ServerStatusCancelled, irma.ServerStatusTimeout} {
		t.Run(string(status), func(t *testing.T) {
			db := newLinkTestDB()
			s := &Server{db: db}

			require.NoError(t, s.processLinkEmailResult(ctx, withStatus(linkResult(linkUsername, linkEmail), status)))
			assert.Empty(t, linkedEmails(t, db))
		})
	}
}
