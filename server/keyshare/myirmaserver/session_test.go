package myirmaserver

import (
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestSessions(t *testing.T) {
	store := newMemorySessionStore()

	s := session{
		Token:  "token",
		Expiry: time.Now().Add(1 * time.Second),
	}
	err := store.add(s)
	assert.NoError(t, err)

	session2, err := store.get(s.Token)
	assert.NoError(t, err)
	assert.Equal(t, s, session2)

	emailSessionToken := irma.RequestorToken("emailtoken")
	err = store.txUpdate(s.Token, func(ses *session) error {
		ses.EmailSessionToken = emailSessionToken
		return nil
	})
	assert.NoError(t, err)

	session3, err := store.get(s.Token)
	assert.NoError(t, err)
	assert.Equal(t, session3.EmailSessionToken, emailSessionToken)

	_, err = store.get("DOESNOTEXIST")
	assert.ErrorIs(t, err, errUnknownSession)

	store.flush()

	session4, err := store.get(s.Token)
	assert.NoError(t, err)
	assert.Equal(t, session4.Token, s.Token)

	time.Sleep(2 * time.Second)

	store.flush()

	_, err = store.get(s.Token)
	assert.ErrorIs(t, err, errUnknownSession)
}
