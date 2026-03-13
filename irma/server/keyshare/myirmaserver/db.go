package myirmaserver

import (
	"context"
	"time"
)

type db interface {
	user(ctx context.Context, id int64) (user, error)

	userIDByUsername(ctx context.Context, username string) (int64, error)

	verifyEmailToken(ctx context.Context, token string) (int64, error)
	verifyLoginToken(ctx context.Context, token, username string) (int64, error)

	scheduleUserRemoval(ctx context.Context, id int64, delay time.Duration) error

	addLoginToken(ctx context.Context, email, token string) error
	loginUserCandidates(ctx context.Context, token string) ([]loginCandidate, error)

	logs(ctx context.Context, id int64, offset int, amount int) ([]logEntry, error)

	addEmail(ctx context.Context, id int64, email string) error
	scheduleEmailRemoval(ctx context.Context, id int64, email string, delay time.Duration) error

	setSeen(ctx context.Context, id int64) error

	hasEmailRevalidation(ctx context.Context) bool
	scheduleEmailRevalidation(ctx context.Context, id int64, email string, delay time.Duration) error
	setPinBlockDate(ctx context.Context, id int64, delay time.Duration) error
}

type userEmail struct {
	Email                string `json:"email"`
	DeleteInProgress     bool   `json:"delete_in_progress"`
	RevalidateInProgress bool   `json:"revalidate_in_progress"`
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
