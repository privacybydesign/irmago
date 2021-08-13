package myirmaserver

import (
	"time"
)

type db interface {
	user(id int64) (user, error)

	userIDByUsername(username string) (int64, error)

	verifyEmailToken(token string) (int64, error)
	verifyLoginToken(token, username string) (int64, error)

	scheduleUserRemoval(id int64, delay time.Duration) error

	addLoginToken(email, token string) error
	loginUserCandidates(token string) ([]loginCandidate, error)

	logs(id int64, offset int, amount int) ([]logEntry, error)

	addEmail(id int64, email string) error
	scheduleEmailRemoval(id int64, email string, delay time.Duration) error

	setSeen(id int64) error
}

type userEmail struct {
	Email            string `json:"email"`
	DeleteInProgress bool   `json:"delete_in_progress"`
}

type user struct {
	Username         string      `json:"username"`
	Emails           []userEmail `json:"emails"`
	language         string
	DeleteInProgress bool `json:"delete_in_progress"`
}

type loginCandidate struct {
	Username   string `json:"username"`
	LastActive int64  `json:"last_active"`
}

type logEntry struct {
	Timestamp int64   `json:"timestamp"`
	Event     string  `json:"event"`
	Param     *string `json:"param,omitempty"`
}
