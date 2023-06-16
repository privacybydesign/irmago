package keyshareserver

import (
	"context"
	"database/sql/driver"

	"github.com/privacybydesign/irmago/internal/keysharecore"

	"github.com/go-errors/errors"
)

var (
	errUserAlreadyExists = errors.New("Cannot create user, username already taken")
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
	AddUser(ctx context.Context, user *User) error
	user(ctx context.Context, username string) (*User, error)
	updateUser(ctx context.Context, user *User) error

	// reservePinTry reserves a pin check attempt, and additionally it returns:
	//  - allowed is whether the user is allowed to do the pin check (false if user is blocked)
	//  - tries is how many tries are remaining, after this pin check
	//  - wait is how long the user must wait before the next attempt is allowed if tries is 0
	// resetPinTries increases the user's try count and (if applicable) the date when the user
	// is unblocked again in the database, regardless of if the pin check succeeds after this
	// invocation.
	reservePinTry(ctx context.Context, user *User) (allowed bool, tries int, wait int64, err error)

	// resetPinTries resets the user's pin count and unblock date fields in the database to their
	// default values (0 past attempts, no unblock date).
	resetPinTries(ctx context.Context, user *User) error

	// User activity registration.
	// setSeen calls are used to track when a users account was last active, for deleting old accounts.
	setSeen(ctx context.Context, user *User) error
	addLog(ctx context.Context, user *User, eventType eventType, param interface{}) error

	// Store email verification tokens on registration
	addEmailVerification(ctx context.Context, user *User, emailAddress, token string, validity int) error
}

// UserSecrets is a keysharecore.UserSecrets with DB (un)marshaling methods.
type UserSecrets keysharecore.UserSecrets

// User represents a user of this server.
type User struct {
	Username string
	Language string
	Secrets  UserSecrets
	id       int64
}

// Scan implements sql/driver Scanner interface.
func (us *UserSecrets) Scan(src interface{}) (err error) {
	bts, ok := src.([]byte)
	if !ok {
		return errors.New("cannot convert source: not a byte slice")
	}
	*us = bts
	return nil
}

// Value implements sql/driver Scanner interface.
func (us UserSecrets) Value() (driver.Value, error) {
	return []byte(us), nil
}
