package usage

import (
	"time"

	"github.com/privacybydesign/irmago/irma"
)

// ReportSchema is the version of the report format sent to the Portal.
const ReportSchema = 1

// Report is one sealed interval of counts. Reports of one run are numbered from 1 by Sequence,
// so the Portal can detect a missing report as a gap; the last report of a cleanly stopped run
// has Final set.
type Report struct {
	Schema         int               `json:"schema"`
	ReportID       string            `json:"report_id"`
	ServerInstance string            `json:"server_instance"`
	RunID          string            `json:"run_id"`
	Sequence       uint64            `json:"sequence"`
	Final          bool              `json:"final"`
	IrmagoVersion  string            `json:"irmago_version"`
	Period         Period            `json:"period"`
	Disclosures    []DisclosureCount `json:"disclosures"`
	Sessions       []SessionCount    `json:"sessions"`
}

type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// DisclosureCount is the number of sessions with an outcome that disclosed (outcome done) or
// requested (other outcomes) a credential type.
type DisclosureCount struct {
	Day            string      `json:"day"`
	Requestor      string      `json:"requestor"`
	Action         irma.Action `json:"action"`
	CredentialType string      `json:"credential_type"`
	Outcome        Outcome     `json:"outcome"`
	Count          int64       `json:"count"`
}

// SessionCount is the number of sessions that reached a final status with an outcome.
type SessionCount struct {
	Day       string      `json:"day"`
	Requestor string      `json:"requestor"`
	Action    irma.Action `json:"action"`
	Outcome   Outcome     `json:"outcome"`
	Count     int64       `json:"count"`
}
