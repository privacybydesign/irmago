package irma

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-errors/errors"
)

// Errors returned by RegisteredClaims.ValidateClaims.
var (
	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenNotValidYet      = errors.New("token is not valid yet")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
)

// NumericDate is a JSON Web Token numeric date: a point in time encoded as the number of
// seconds since the epoch (RFC 7519, section 2). Sub-second precision is dropped on encoding,
// as the IRMA protocol has never used it.
type NumericDate struct {
	time.Time
}

// NewNumericDate returns t as a NumericDate.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{Time: t.Truncate(time.Second)}
}

func (d NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(d.Time.Unix(), 10)), nil
}

func (d *NumericDate) UnmarshalJSON(bts []byte) error {
	var seconds float64
	if err := json.Unmarshal(bts, &seconds); err != nil {
		return errors.WrapPrefix(err, "failed to parse JWT numeric date", 0)
	}
	whole, fraction := int64(seconds), seconds-float64(int64(seconds))
	*d = NumericDate{Time: time.Unix(whole, int64(fraction*float64(time.Second)))}
	return nil
}

// ClaimStrings is the type of the "aud" claim, which RFC 7519 allows to be either a single
// string or an array of strings.
type ClaimStrings []string

func (c ClaimStrings) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(c))
}

func (c *ClaimStrings) UnmarshalJSON(bts []byte) error {
	var value any
	if err := json.Unmarshal(bts, &value); err != nil {
		return errors.WrapPrefix(err, "failed to parse JWT audience", 0)
	}
	switch v := value.(type) {
	case nil:
		*c = nil
	case string:
		*c = ClaimStrings{v}
	case []any:
		audience := make(ClaimStrings, len(v))
		for i, entry := range v {
			str, ok := entry.(string)
			if !ok {
				return errors.Errorf("JWT audience entry %d is not a string", i)
			}
			audience[i] = str
		}
		*c = audience
	default:
		return errors.New("JWT audience is neither a string nor an array of strings")
	}
	return nil
}

// RegisteredClaims holds the JWT claims registered by RFC 7519 that the IRMA protocol uses.
// Claims structs embed it to inherit both the wire format and the time claim checks that
// ValidateClaims performs.
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

// ValidateClaims checks the time claims that are present against now. Each of them is
// optional; a claim that is absent is not a reason to reject the token.
func (c RegisteredClaims) ValidateClaims(now time.Time) error {
	if c.ExpiresAt != nil && !now.Before(c.ExpiresAt.Time) {
		return ErrTokenExpired
	}
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return ErrTokenNotValidYet
	}
	if c.IssuedAt != nil && now.Before(c.IssuedAt.Time) {
		return ErrTokenUsedBeforeIssued
	}
	return nil
}
