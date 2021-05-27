package myirmaserver

import (
	"time"
)

type DB interface {
	User(id int64) (User, error)

	UserIDByUsername(username string) (int64, error)
	UserIDByEmailToken(token string) (int64, error)
	UserIDByLoginToken(token, username string) (int64, error)

	ScheduleUserRemoval(id int64, delay time.Duration) error

	AddEmailLoginToken(email, token string) error
	LoginUserCandidates(token string) ([]LoginCandidate, error)

	Logs(id int64, offset int, amount int) ([]LogEntry, error)

	AddEmail(id int64, email string) error
	ScheduleEmailRemoval(id int64, email string, delay time.Duration) error

	SetSeen(id int64) error
}

type UserEmail struct {
	Email            string `json:"email"`
	DeleteInProgress bool   `json:"delete_in_progress"`
}

type User struct {
	Username         string      `json:"username"`
	Emails           []UserEmail `json:"emails"`
	language         string
	DeleteInProgress bool `json:"delete_in_progress"`
}

type LoginCandidate struct {
	Username   string `json:"username"`
	LastActive int64  `json:"last_active"`
}

type LogEntry struct {
	Timestamp int64   `json:"timestamp"`
	Event     string  `json:"event"`
	Param     *string `json:"param,omitempty"`
}
