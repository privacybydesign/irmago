package usage

import (
	"time"

	"github.com/privacybydesign/irmago/irma"
)

// ReportSchema is the version of the report format sent to the Portal. Fields added in a way an
// older Portal can ignore, such as Heartbeat, do not change it.
const ReportSchema = 1

// Report is one sealed interval of counts. Reports of one run are numbered from 1 by Sequence,
// so the Portal can detect a missing report as a gap; the last report of a cleanly stopped run
// has Final set. The periods of a run's reports follow each other without holes, from the start
// of the run to its last report.
type Report struct {
	Schema         int    `json:"schema"`
	ReportID       string `json:"report_id"`
	ServerInstance string `json:"server_instance"`
	RunID          string `json:"run_id"`
	Sequence       uint64 `json:"sequence"`
	Final          bool   `json:"final"`
	IrmagoVersion  string `json:"irmago_version"`
	// Heartbeat is the longest time in seconds between two reports of a run, also when no
	// sessions end. A run whose last report is older than this has stopped reporting. Servers
	// that skip empty intervals leave it out.
	Heartbeat   int64             `json:"heartbeat_seconds,omitempty"`
	Period      Period            `json:"period"`
	Disclosures []DisclosureCount `json:"disclosures"`
	Sessions    []SessionCount    `json:"sessions"`
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
