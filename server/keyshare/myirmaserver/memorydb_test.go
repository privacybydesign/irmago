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

	id, err := db.UserIDByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	id, err = db.UserIDByEmailToken("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.UserIDByEmailToken("testtoken")
	assert.Error(t, err)

	_, err = db.UserIDByUsername("DNE")
	assert.Error(t, err)

	err = db.SetSeen(15)
	assert.NoError(t, err)

	err = db.SetSeen(123456)
	assert.Error(t, err)

	assert.NotEqual(t, time.Unix(0, 0), db.userData["testuser"].lastActive)

	err = db.ScheduleUserRemoval(15, 0)
	assert.NoError(t, err)

	_, err = db.UserIDByUsername("testuser")
	assert.Error(t, err)

	err = db.ScheduleUserRemoval(15, 0)
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

	err := db.AddEmailLoginToken("test2@test.com", "test2token")
	assert.Error(t, err)

	err = db.AddEmailLoginToken("test@test.com", "testtoken")
	require.NoError(t, err)

	cand, err := db.LoginUserCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []LoginCandidate{{Username: "testuser", LastActive: 0}}, cand)

	_, err = db.LoginUserCandidates("DNE")
	assert.Error(t, err)

	_, err = db.UserIDByLoginToken("testtoken", "DNE")
	assert.Error(t, err)

	id, err := db.UserIDByLoginToken("testtoken", "noemail")
	assert.Equal(t, int64(0), id)
	assert.Error(t, err)

	id, err = db.UserIDByLoginToken("testtoken", "testuser")
	assert.Equal(t, int64(15), id)
	assert.NoError(t, err)

	id, err = db.UserIDByLoginToken("testtoken", "testuser")
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
				logEntries: []LogEntry{
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

	info, err := db.User(15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	info, err = db.User(17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []UserEmail(nil), info.Emails)

	_, err = db.User(1231)
	assert.Error(t, err)

	entries, err := db.Logs(15, 0, 2)
	assert.NoError(t, err)
	assert.Equal(t, []LogEntry{
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

	entries, err = db.Logs(15, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.Logs(15, 1, 15)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.Logs(15, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	_, err = db.Logs(20, 100, 20)
	assert.Error(t, err)

	err = db.AddEmail(17, "test@test.com")
	assert.NoError(t, err)

	info, err = db.User(17)
	assert.NoError(t, err)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	err = db.AddEmail(20, "bla@bla.com")
	assert.Error(t, err)

	err = db.ScheduleEmailRemoval(17, "test@test.com", 0)
	assert.NoError(t, err)

	info, err = db.User(17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.ScheduleEmailRemoval(17, "bla@bla.com", 0)
	assert.NoError(t, err)

	err = db.ScheduleEmailRemoval(20, "bl@bla.com", 0)
	assert.Error(t, err)
}
