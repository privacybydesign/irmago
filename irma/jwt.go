package irma

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-errors/errors"
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

// Why this type is declared here rather than taken from a library.
//
// The public claims structs of this package used to embed golang-jwt's RegisteredClaims, and jwx
// offers no struct to embed in its place: its jwt.Token is an interface over dynamically typed
// claims, which a struct cannot inherit a wire format from. So this type carries the wire format
// only; checking the time claims is jwx's job, in internal/jose. The encoding reproduces
// golang-jwt's byte for byte, so that a client and a server of different irmago versions keep
// understanding each other's tokens; TestRegisteredClaimsWireFormat pins it. Only the claims the
// IRMA protocol actually sends are here, and adding one means adding it to that test too.

// RegisteredClaims holds the JWT claims registered by RFC 7519 that the IRMA protocol uses.
// Claims structs embed it to inherit its wire format. The claims themselves are checked by jwx
// during verification, not here.
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}
