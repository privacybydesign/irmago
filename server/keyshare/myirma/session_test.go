package myirma

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessions(t *testing.T) {
	store := NewMemorySessionStore(1 * time.Second)

	session := store.create()
	assert.NotEqual(t, (*Sessiondata)(nil), session)

	session2 := store.get(session.token)
	assert.Equal(t, session, session2)

	session3 := store.get("DOESNOTEXIST")
	assert.Equal(t, (*Sessiondata)(nil), session3)

	store.flush()

	session4 := store.get(session.token)
	assert.Equal(t, session, session4)

	time.Sleep(2 * time.Second)

	store.flush()

	session5 := store.get(session.token)
	assert.Equal(t, (*Sessiondata)(nil), session5)
}
