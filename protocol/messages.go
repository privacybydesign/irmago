package protocol

import (
	"fmt"
	"strconv"
	"time"
)

const (
	DISCLOSING = "disclosing"
	ISSUING    = "issuing"
	SIGNING    = "signing"
)

type Timestamp time.Time

type Qr struct {
	Url                string `json:"u"`
	ProtocolVersion    string `json:"v"`
	ProtocolMaxVersion string `json:"vmax"`
	Type               string `json:"irmaqr"`
}

func (t *Timestamp) MarshalJSON() ([]byte, error) {
	ts := time.Time(*t).Unix()
	stamp := fmt.Sprint(ts)
	return []byte(stamp), nil
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	ts, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(int64(ts), 0))
	return nil
}
