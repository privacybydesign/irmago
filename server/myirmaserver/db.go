package myirmaserver

import (
	"errors"
)

var (
	ErrUserNotFound = errors.New("Could not find specified user")
)

type MyirmaDB interface {
	GetUserID(username string) (int64, error)
	VerifyEmailToken(token string) (int64, error)
	RemoveUser(id int64) error

	AddEmailLoginToken(email, token string) error
	LoginTokenGetCandidates(token string) ([]LoginCandidate, error)
	LoginTokenGetEmail(token string) (string, error)
	TryUserLoginToken(token, username string) (bool, error)

	GetUserInformation(id int64) (UserInformation, error)
	GetLogs(id int64, offset int, ammount int) ([]LogEntry, error)
	AddEmail(id int64, email string) error
	RemoveEmail(id int64, email string) error

	SetSeen(id int64) error
}

type UserEmail struct {
	Email            string `json:"email"`
	DeleteInProgress bool   `json:"delete_in_progress"`
}

type UserInformation struct {
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
	Timestamp int64  `json:"timestamp"`
	Event     string `json:"event"`
	Param     string `json:"param"`
}
