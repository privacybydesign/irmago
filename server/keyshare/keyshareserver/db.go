package keyshareserver

import (
	"github.com/privacybydesign/irmago/internal/keysharecore"

	"github.com/go-errors/errors"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrUserNotFound      = errors.New("Could not find specified user")
	ErrInvalidRecord     = errors.New("Invalid record in database")
)

type LogEntryType string

const (
	PinCheckRefused LogEntryType = "PIN_CHECK_REFUSED"
	PinCheckSuccess LogEntryType = "PIN_CHECK_SUCCESS"
	PinCheckFailed  LogEntryType = "PIN_CHECK_FAILED"
	PinCheckBlocked LogEntryType = "PIN_CHECK_BLOCKED"
	IrmaSession     LogEntryType = "IRMA_SESSION"
)

// Interface used by server to manage data storage
// there are multiple implementations of this, currently:
//  - memorydb (memorydb.go) storing all data in memory (forgets everything after reboot)
//  - postgresdb (postgresdb.go) storing all data in a postgres database
type KeyshareDB interface {
	// User management
	NewUser(user *KeyshareUser) error
	User(username string) (*KeyshareUser, error)
	UpdateUser(user *KeyshareUser) error

	// ReservePincheck reserves a pin check attempt. Return parameters:
	//  - allowed is whether the user is allowed to do the pin check (false if user is blocked)
	//  - tries is how many tries are remaining, after this pin check
	//  - wait is how long the user must wait before the next attempt is allowed if tries is 0
	// ReservePincheck increases the user's try count and (if applicable) the date when the user
	// is unblocked again in the database, regardless of if the pin check succeeds after this
	// invocation.
	ReservePincheck(user *KeyshareUser) (allowed bool, tries int, wait int64, err error)

	// ClearPincheck resets the user's pin count and unblock date fields in the database to their
	// default values (0 past attempts, no unblock date).
	ClearPincheck(user *KeyshareUser) error

	// User activity registration
	// SetSeen calls are used to track when a users account was last active, for deleting old accounts
	SetSeen(user *KeyshareUser) error
	AddLog(user *KeyshareUser, eventType LogEntryType, param interface{}) error

	// Store email verification tokens on registration
	AddEmailVerification(user *KeyshareUser, emailAddress, token string) error
}

// Actual data on a user used by this server.
type KeyshareUser struct {
	Username string
	Language string
	Coredata keysharecore.EncryptedKeysharePacket
	id       int64
}
