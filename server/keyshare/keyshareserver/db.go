package keyshareserver

import (
	"github.com/privacybydesign/irmago/internal/keysharecore"

	"github.com/go-errors/errors"
)

var (
	errUserAlreadyExists = errors.New("Cannot create user, username already taken")
	errInvalidRecord     = errors.New("Invalid record in database")
)

type eventType string

const (
	eventTypePinCheckRefused eventType = "PIN_CHECK_REFUSED"
	eventTypePinCheckSuccess eventType = "PIN_CHECK_SUCCESS"
	eventTypePinCheckFailed  eventType = "PIN_CHECK_FAILED"
	eventTypePinCheckBlocked eventType = "PIN_CHECK_BLOCKED"
	eventTypeIRMASession     eventType = "IRMA_SESSION"
)

// DB is an interface used by server to manage data storage.
// There are multiple implementations of this, currently:
//   - memorydb (memorydb.go) storing all data in memory (forgets everything after reboot)
//   - postgresdb (postgresdb.go) storing all data in a postgres database
type DB interface {
	AddUser(user *User) error
	user(username string) (*User, error)
	updateUser(user *User) error

	// reservePinTry reserves a pin check attempt, and additionally it returns:
	//  - allowed is whether the user is allowed to do the pin check (false if user is blocked)
	//  - tries is how many tries are remaining, after this pin check
	//  - wait is how long the user must wait before the next attempt is allowed if tries is 0
	// resetPinTries increases the user's try count and (if applicable) the date when the user
	// is unblocked again in the database, regardless of if the pin check succeeds after this
	// invocation.
	reservePinTry(user *User) (allowed bool, tries int, wait int64, err error)

	// resetPinTries resets the user's pin count and unblock date fields in the database to their
	// default values (0 past attempts, no unblock date).
	resetPinTries(user *User) error

	// User activity registration.
	// setSeen calls are used to track when a users account was last active, for deleting old accounts.
	setSeen(user *User) error
	addLog(user *User, eventType eventType, param interface{}) error

	// Store email verification tokens on registration
	addEmailVerification(user *User, emailAddress, token string, validity int) error
}

// User represents a user of this server.
type User struct {
	Username string
	Language string
	Secrets  keysharecore.UserSecrets
	id       int64
}
