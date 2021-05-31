package myirmaserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessions(t *testing.T) {
	store := newMemorySessionStore(1 * time.Second)

	s := store.create()
	assert.NotEqual(t, (*session)(nil), s)

	session2 := store.get(s.token)
	assert.Equal(t, s, session2)

	session3 := store.get("DOESNOTEXIST")
	assert.Equal(t, (*session)(nil), session3)

	store.flush()

	session4 := store.get(s.token)
	assert.Equal(t, s, session4)

	time.Sleep(2 * time.Second)

	store.flush()

	session5 := store.get(s.token)
	assert.Equal(t, (*session)(nil), session5)
}
