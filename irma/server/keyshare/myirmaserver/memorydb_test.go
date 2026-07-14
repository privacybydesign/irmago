package myirmaserver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryDBUserManagement(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
			},
		},
		verifyEmailTokens: map[string]int64{
			"testtoken": 15,
		},
	}

	id, err := db.userIDByUsername(context.Background(), "testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	id, err = db.verifyEmailToken(context.Background(), "testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.verifyEmailToken(context.Background(), "testtoken")
	assert.Error(t, err)

	_, err = db.userIDByUsername(context.Background(), "DNE")
	assert.Error(t, err)

	err = db.setSeen(context.Background(), 15)
	assert.NoError(t, err)

	err = db.setSeen(context.Background(), 123456)
	assert.Error(t, err)

	assert.NotEqual(t, time.Unix(0, 0), db.userData["testuser"].lastActive)

	err = db.scheduleUserRemoval(context.Background(), 15, 0)
	assert.NoError(t, err)

	_, err = db.userIDByUsername(context.Background(), "testuser")
	assert.Error(t, err)

	err = db.scheduleUserRemoval(context.Background(), 15, 0)
	assert.Error(t, err)
}

func TestMemoryDBLoginToken(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@example.com"},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(0, 0),
			},
		},
		loginEmailTokens: map[string]string{},
	}

	err := db.addLoginToken(context.Background(), "test2@example.com", "test2token")
	assert.Error(t, err)

	err = db.addLoginToken(context.Background(), "test@example.com", "testtoken")
	require.NoError(t, err)

	cand, err := db.loginUserCandidates(context.Background(), "testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []loginCandidate{{Username: "testuser", LastActive: 0}}, cand)

	_, err = db.loginUserCandidates(context.Background(), "DNE")
	assert.Error(t, err)

	_, err = db.verifyLoginToken(context.Background(), "testtoken", "DNE")
	assert.Error(t, err)

	id, err := db.verifyLoginToken(context.Background(), "testtoken", "noemail")
	assert.Equal(t, int64(0), id)
	assert.Error(t, err)

	id, err = db.verifyLoginToken(context.Background(), "testtoken", "testuser")
	assert.Equal(t, int64(15), id)
	assert.NoError(t, err)

	id, err = db.verifyLoginToken(context.Background(), "testtoken", "testuser")
	assert.Equal(t, int64(0), id)
	assert.Error(t, err)
}

func TestMemoryDBUserInfo(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(15, 0),
				email:      []string{"test@example.com"},
				logEntries: []logEntry{
					{
						Timestamp: 110,
						Event:     "test",
						Param:     &strEmpty,
					},
					{
						Timestamp: 120,
						Event:     "test2",
						Param:     &str15,
					},
				},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(20, 0),
			},
		},
	}

	info, err := db.user(context.Background(), 15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []userEmail{{Email: "test@example.com", DeleteInProgress: false}}, info.Emails)

	info, err = db.user(context.Background(), 17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []userEmail(nil), info.Emails)

	_, err = db.user(context.Background(), 1231)
	assert.Error(t, err)

	entries, err := db.logs(context.Background(), 15, 0, 2)
	assert.NoError(t, err)
	assert.Equal(t, []logEntry{
		{
			Timestamp: 110,
			Event:     "test",
			Param:     &strEmpty,
		},
		{
			Timestamp: 120,
			Event:     "test2",
			Param:     &str15,
		},
	}, entries)

	entries, err = db.logs(context.Background(), 15, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.logs(context.Background(), 15, 1, 15)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.logs(context.Background(), 15, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	_, err = db.logs(context.Background(), 20, 100, 20)
	assert.Error(t, err)

	err = db.addEmail(context.Background(), 17, "test@example.com")
	assert.NoError(t, err)

	info, err = db.user(context.Background(), 17)
	assert.NoError(t, err)
	assert.Equal(t, []userEmail{{Email: "test@example.com", DeleteInProgress: false}}, info.Emails)

	err = db.addEmail(context.Background(), 20, "bla@bla.com")
	assert.Error(t, err)

	err = db.scheduleEmailRemoval(context.Background(), 17, "test@example.com", 0)
	assert.NoError(t, err)

	info, err = db.user(context.Background(), 17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.scheduleEmailRemoval(context.Background(), 17, "bla@bla.com", 0)
	assert.NoError(t, err)

	err = db.scheduleEmailRemoval(context.Background(), 20, "bl@bla.com", 0)
	assert.Error(t, err)
}
