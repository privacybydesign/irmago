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
	PinCheckRefused = "PIN_CHECK_REFUSED"
	PinCheckSuccess = "PIN_CHECK_SUCCESS"
	PinCheckFailed  = "PIN_CHECK_FAILED"
	PinCheckBlocked = "PIN_CHECK_BLOCKED"
	IrmaSession     = "IRMA_SESSION"
)

// Interface used by server to manage data storage
// there are multiple implementations of this, currently:
//  - memorydb (memorydb.go) storing all data in memory (forgets everything after reboot)
//  - postgresdb (postgresdb.go) storing all data in a postgres database
type KeyshareDB interface {
	// User management
	NewUser(user KeyshareUserData) (KeyshareUser, error)
	User(username string) (KeyshareUser, error)
	UpdateUser(user KeyshareUser) error

	// Pin checking logic
	// Reserve returns (allow, tries, wait, error)
	// where allow is whether we can do the actual pin check
	// tries is how many tries are remaining after doing so
	// wait is how long to wait if tries is 0 or allow false
	ReservePincheck(user KeyshareUser) (bool, int, int64, error)
	ClearPincheck(user KeyshareUser) error

	// User activity registration
	// SetSeen calls are used to track when a users account was last active, for deleting old accounts
	SetSeen(user KeyshareUser) error
	AddLog(user KeyshareUser, eventType LogEntryType, param interface{}) error

	// Store email verification tokens on registration
	AddEmailVerification(user KeyshareUser, emailAddress, token string) error
}

// We wrap KeyshareUserData in an interface to allow implementation-specific data
// to also be returned. This is used in postgresdb to deal with database identifiers
type KeyshareUser interface {
	Data() *KeyshareUserData
}

// Actual data on a user used by this server.
type KeyshareUserData struct {
	Username string
	Language string
	Coredata keysharecore.EncryptedKeysharePacket
}
