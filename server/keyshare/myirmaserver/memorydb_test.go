package myirmaserver

import (
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

	id, err := db.userIDByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	id, err = db.userIDByEmailToken("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.userIDByEmailToken("testtoken")
	assert.Error(t, err)

	_, err = db.userIDByUsername("DNE")
	assert.Error(t, err)

	err = db.setSeen(15)
	assert.NoError(t, err)

	err = db.setSeen(123456)
	assert.Error(t, err)

	assert.NotEqual(t, time.Unix(0, 0), db.userData["testuser"].lastActive)

	err = db.scheduleUserRemoval(15, 0)
	assert.NoError(t, err)

	_, err = db.userIDByUsername("testuser")
	assert.Error(t, err)

	err = db.scheduleUserRemoval(15, 0)
	assert.Error(t, err)
}

func TestMemoryDBLoginToken(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@test.com"},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(0, 0),
			},
		},
		loginEmailTokens: map[string]string{},
	}

	err := db.addEmailLoginToken("test2@test.com", "test2token")
	assert.Error(t, err)

	err = db.addEmailLoginToken("test@test.com", "testtoken")
	require.NoError(t, err)

	cand, err := db.loginUserCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []loginCandidate{{Username: "testuser", LastActive: 0}}, cand)

	_, err = db.loginUserCandidates("DNE")
	assert.Error(t, err)

	_, err = db.userIDByLoginToken("testtoken", "DNE")
	assert.Error(t, err)

	id, err := db.userIDByLoginToken("testtoken", "noemail")
	assert.Equal(t, int64(0), id)
	assert.Error(t, err)

	id, err = db.userIDByLoginToken("testtoken", "testuser")
	assert.Equal(t, int64(15), id)
	assert.NoError(t, err)

	id, err = db.userIDByLoginToken("testtoken", "testuser")
	assert.Equal(t, int64(0), id)
	assert.Error(t, err)
}

func TestMemoryDBUserInfo(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(15, 0),
				email:      []string{"test@test.com"},
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

	info, err := db.user(15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []userEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []userEmail(nil), info.Emails)

	_, err = db.user(1231)
	assert.Error(t, err)

	entries, err := db.logs(15, 0, 2)
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

	entries, err = db.logs(15, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.logs(15, 1, 15)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.logs(15, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	_, err = db.logs(20, 100, 20)
	assert.Error(t, err)

	err = db.addEmail(17, "test@test.com")
	assert.NoError(t, err)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, []userEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	err = db.addEmail(20, "bla@bla.com")
	assert.Error(t, err)

	err = db.scheduleEmailRemoval(17, "test@test.com", 0)
	assert.NoError(t, err)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.scheduleEmailRemoval(17, "bla@bla.com", 0)
	assert.NoError(t, err)

	err = db.scheduleEmailRemoval(20, "bl@bla.com", 0)
	assert.Error(t, err)
}
