package keyshareserver

import (
	"github.com/privacybydesign/irmago/internal/keysharecore"

	"github.com/go-errors/errors"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrInvalidRecord     = errors.New("Invalid record in database")
)

type EventType string

const (
	EventTypePinCheckRefused EventType = "PIN_CHECK_REFUSED"
	EventTypePinCheckSuccess EventType = "PIN_CHECK_SUCCESS"
	EventTypePinCheckFailed  EventType = "PIN_CHECK_FAILED"
	EventTypePinCheckBlocked EventType = "PIN_CHECK_BLOCKED"
	EventTypeIRMASession     EventType = "IRMA_SESSION"
)

// Interface used by server to manage data storage
// there are multiple implementations of this, currently:
//  - memorydb (memorydb.go) storing all data in memory (forgets everything after reboot)
//  - postgresdb (postgresdb.go) storing all data in a postgres database
type DB interface {
	// User management
	AddUser(user *User) error
	User(username string) (*User, error)
	UpdateUser(user *User) error

	// ReservePinTry reserves a pin check attempt, and additionally it returns:
	//  - allowed is whether the user is allowed to do the pin check (false if user is blocked)
	//  - tries is how many tries are remaining, after this pin check
	//  - wait is how long the user must wait before the next attempt is allowed if tries is 0
	// ResetPinTries increases the user's try count and (if applicable) the date when the user
	// is unblocked again in the database, regardless of if the pin check succeeds after this
	// invocation.
	ReservePinTry(user *User) (allowed bool, tries int, wait int64, err error)

	// ResetPinTries resets the user's pin count and unblock date fields in the database to their
	// default values (0 past attempts, no unblock date).
	ResetPinTries(user *User) error

	// User activity registration
	// SetSeen calls are used to track when a users account was last active, for deleting old accounts
	SetSeen(user *User) error
	AddLog(user *User, eventType EventType, param interface{}) error

	// Store email verification tokens on registration
	AddEmailVerification(user *User, emailAddress, token string) error
}

// Actual data on a user used by this server.
type User struct {
	Username string
	Language string
	UserData keysharecore.User
	id       int64
}
