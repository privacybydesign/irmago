package keysharecore

import (
	"crypto/rand"

	"github.com/go-errors/errors"
)

// ChangePinLegacy is like ChangePin() but for legacy clients that have not yet upgraded to
// challenge-response.
func (c *Core) ChangePinLegacy(secrets UserSecrets, oldpinRaw, newpinRaw string) (UserSecrets, error) {
	s, err := c.decryptUserSecretsIfPinOK(secrets, oldpinRaw)
	if err != nil {
		return nil, err
	}
	if s.PublicKey != nil {
		return nil, errors.New("JWT required")
	}

	// change and reencrypt
	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return nil, err
	}
	if err = s.setPin(newpinRaw); err != nil {
		return nil, err
	}
	if err = s.setID(id); err != nil {
		return nil, err
	}
	return c.encryptUserSecrets(s)
}
