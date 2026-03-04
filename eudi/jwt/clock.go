package eudi_jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

type SystemClock struct{}

func NewSystemClock() jwt.Clock {
	return &SystemClock{}
}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

type StaticClock struct {
	CurrentTime int64
}

func (c *StaticClock) Now() time.Time {
	return time.Unix(c.CurrentTime, 0)
}
