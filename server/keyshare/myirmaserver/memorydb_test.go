package myirmaserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryDBUserManagement(t *testing.T) {
	db := &myirmaMemoryDB{
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

	id, err := db.UserID("testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	id, err = db.VerifyEmailToken("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.VerifyEmailToken("testtoken")
	assert.Error(t, err)

	_, err = db.UserID("DNE")
	assert.Error(t, err)

	err = db.SetSeen(15)
	assert.NoError(t, err)

	err = db.SetSeen(123456)
	assert.Error(t, err)

	assert.NotEqual(t, time.Unix(0, 0), db.userData["testuser"].lastActive)

	err = db.RemoveUser(15, 0)
	assert.NoError(t, err)

	_, err = db.UserID("testuser")
	assert.Error(t, err)

	err = db.RemoveUser(15, 0)
	assert.Error(t, err)
}

func TestMemoryDBLoginToken(t *testing.T) {
	db := &myirmaMemoryDB{
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

	cand, err := db.LoginTokenCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []LoginCandidate{{Username: "testuser", LastActive: 0}}, cand)

	_, err = db.LoginTokenCandidates("DNE")
	assert.Error(t, err)

	_, _, err = db.TryUserLoginToken("testtoken", "DNE")
	assert.Error(t, err)

	id, ok, err := db.TryUserLoginToken("testtoken", "noemail")
	assert.Equal(t, int64(0), id)
	assert.NoError(t, err)
	assert.False(t, ok)

	id, ok, err = db.TryUserLoginToken("testtoken", "testuser")
	assert.Equal(t, int64(15), id)
	assert.NoError(t, err)
	assert.True(t, ok)

	id, ok, err = db.TryUserLoginToken("testtoken", "testuser")
	assert.Equal(t, int64(0), id)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryDBUserInfo(t *testing.T) {
	db := &myirmaMemoryDB{
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

	info, err := db.UserInformation(15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	info, err = db.UserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []UserEmail(nil), info.Emails)

	_, err = db.UserInformation(1231)
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

	info, err = db.UserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	err = db.AddEmail(20, "bla@bla.com")
	assert.Error(t, err)

	err = db.RemoveEmail(17, "test@test.com", 0)
	assert.NoError(t, err)

	info, err = db.UserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.RemoveEmail(17, "bla@bla.com", 0)
	assert.NoError(t, err)

	err = db.RemoveEmail(20, "bl@bla.com", 0)
	assert.Error(t, err)
}
