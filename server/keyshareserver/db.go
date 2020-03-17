package keyshareserver

import (
	"errors"

	"github.com/privacybydesign/irmago/internal/keysharecore"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrUserNotFound      = errors.New("Could not find specified user")
	ErrInvalidRecord     = errors.New("Invalid record in database")
)

type LogEntryType string

const (
	PinCheckRefused = "PIN_CHECK_REFUSED"
	PinCheckSucces  = "PIN_CHECK_SUCCESS"
	PinCheckFailed  = "PIN_CHECK_FAILED"
	PinCheckBlocked = "PIN_CHECK_BLOCKED"
	IrmaSession     = "IRMA_SESSION"
)

type KeyshareDB interface {
	NewUser(user KeyshareUserData) (KeyshareUser, error)
	User(username string) (KeyshareUser, error)
	UpdateUser(user KeyshareUser) error

	// Reserve returns (allow, tries, wait, error)
	ReservePincheck(user KeyshareUser) (bool, int, int64, error)
	ClearPincheck(user KeyshareUser) error

	SetSeen(user KeyshareUser) error
	AddLog(user KeyshareUser, eventType LogEntryType, param interface{}) error

	AddEmailVerification(user KeyshareUser, emailAddress, token string) error
}

type KeyshareUser interface {
	Data() *KeyshareUserData
}

type KeyshareUserData struct {
	Username string
	Language string
	Coredata keysharecore.EncryptedKeysharePacket
}
