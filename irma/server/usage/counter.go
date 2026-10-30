// Package usage counts IRMA sessions that reach a final status and reports those counts to the
// Yivi Portal. Counts are kept in memory per day, requestor, action, outcome and credential type,
// and leave the server as small delta reports, signed with an account key that the operator
// registers in the Portal. No attribute values or session identifiers are ever reported.
package usage

import (
	"sort"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/irma"
)

// Outcome is how a session ended, as reported to the Portal.
type Outcome string

const (
	OutcomeDone      Outcome = "done"
	OutcomeCancelled Outcome = "cancelled"
	OutcomeFailed    Outcome = "failed"
	OutcomeTimeout   Outcome = "timeout"
)

// Event describes one session that reached a final status.
type Event struct {
	Time      time.Time
	Requestor string
	Action    irma.Action
	Outcome   Outcome
	// CredentialTypes are the credential types the session disclosed (outcome done) or
	// requested (other outcomes), without duplicates.
	CredentialTypes []irma.CredentialTypeIdentifier
}

// Counter receives an Event for every session that reaches a final status.
// Record must never block or fail a session.
type Counter interface {
	Record(Event)
}

// NoopCounter discards all events. It is used when usage reporting is disabled.
type NoopCounter struct{}

func (NoopCounter) Record(Event) {}

type sessionKey struct {
	Day       string
	Requestor string
	Action    irma.Action
	Outcome   Outcome
}

type disclosureKey struct {
	Day            string
	Requestor      string
	Action         irma.Action
	CredentialType irma.CredentialTypeIdentifier
	Outcome        Outcome
}

// tally holds the counts of the open interval.
type tally struct {
	sync.Mutex
	sessions    map[sessionKey]int64
	disclosures map[disclosureKey]int64
}

func newTally() *tally {
	return &tally{
		sessions:    map[sessionKey]int64{},
		disclosures: map[disclosureKey]int64{},
	}
}

func (t *tally) record(e Event) {
	day := e.Time.UTC().Format(time.DateOnly)
	t.Lock()
	defer t.Unlock()
	t.sessions[sessionKey{day, e.Requestor, e.Action, e.Outcome}]++
	for _, ct := range e.CredentialTypes {
		t.disclosures[disclosureKey{day, e.Requestor, e.Action, ct, e.Outcome}]++
	}
}

func (t *tally) empty() bool {
	t.Lock()
	defer t.Unlock()
	return len(t.sessions) == 0
}

// take returns the counts collected so far as report rows and resets the tally.
func (t *tally) take() ([]DisclosureCount, []SessionCount) {
	t.Lock()
	sessions, disclosures := t.sessions, t.disclosures
	t.sessions, t.disclosures = map[sessionKey]int64{}, map[disclosureKey]int64{}
	t.Unlock()

	sessionRows := make([]SessionCount, 0, len(sessions))
	for k, n := range sessions {
		sessionRows = append(sessionRows, SessionCount{
			Day: k.Day, Requestor: k.Requestor, Action: k.Action, Outcome: k.Outcome, Count: n,
		})
	}
	disclosureRows := make([]DisclosureCount, 0, len(disclosures))
	for k, n := range disclosures {
		disclosureRows = append(disclosureRows, DisclosureCount{
			Day: k.Day, Requestor: k.Requestor, Action: k.Action, CredentialType: k.CredentialType.String(),
			Outcome: k.Outcome, Count: n,
		})
	}

	// Sorted output keeps reports deterministic, which makes them easier to read and test.
	sort.Slice(sessionRows, func(i, j int) bool {
		a, b := sessionRows[i], sessionRows[j]
		return a.Day+a.Requestor+string(a.Action)+string(a.Outcome) < b.Day+b.Requestor+string(b.Action)+string(b.Outcome)
	})
	sort.Slice(disclosureRows, func(i, j int) bool {
		a, b := disclosureRows[i], disclosureRows[j]
		return a.Day+a.Requestor+string(a.Action)+a.CredentialType+string(a.Outcome) <
			b.Day+b.Requestor+string(b.Action)+b.CredentialType+string(b.Outcome)
	})
	return disclosureRows, sessionRows
}
