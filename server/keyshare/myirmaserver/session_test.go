package myirmaserver

import (
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestSessions(t *testing.T) {
	store := newMemorySessionStore(1 * time.Second)

	s := session{
		token:  "token",
		expiry: time.Now().Add(1 * time.Second),
	}
	err := store.add(s)
	assert.NoError(t, err)

	session2, err := store.get(s.token)
	assert.NoError(t, err)
	assert.Equal(t, s, session2)

	emailSessionToken := irma.RequestorToken("emailtoken")
	err = store.txUpdate(s.token, func(ses *session) error {
		ses.emailSessionToken = emailSessionToken
		return nil
	})
	assert.NoError(t, err)

	session3, err := store.get(s.token)
	assert.NoError(t, err)
	assert.Equal(t, session3.emailSessionToken, emailSessionToken)

	_, err = store.get("DOESNOTEXIST")
	assert.ErrorIs(t, err, errUnknownSession)

	store.flush()

	session4, err := store.get(s.token)
	assert.NoError(t, err)
	assert.Equal(t, session4.token, s.token)

	time.Sleep(2 * time.Second)

	store.flush()

	_, err = store.get(s.token)
	assert.ErrorIs(t, err, errUnknownSession)
}
