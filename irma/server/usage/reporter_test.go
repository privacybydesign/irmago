package usage_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server/usage"
	"github.com/privacybydesign/irmago/irma/server/usage/usagetest"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	email = irma.NewCredentialTypeIdentifier("irma-demo.sidn-pbdf.email")
	root  = irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
)

func newSettings(t *testing.T, portal *usagetest.Portal) usage.Settings {
	usage.SetMinInterval(t, time.Second)
	return usage.Settings{
		PortalURL:      portal.DirectoryURL(),
		Interval:       time.Second,
		StateDir:       t.TempDir(),
		ServerInstance: "test-instance",
	}
}

func register(t *testing.T, portal *usagetest.Portal, settings usage.Settings) {
	key, err := usage.LoadOrCreateKey(settings.AccountKeyFile, settings.StateDir)
	require.NoError(t, err)
	portal.Register(usage.Thumbprint(key))
}

func TestReporterSendsSignedReports(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	register(t, portal, settings)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)

	day := time.Now().UTC().Format(time.DateOnly)
	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone,
		CredentialTypes: []irma.CredentialTypeIdentifier{email, root}})
	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone,
		CredentialTypes: []irma.CredentialTypeIdentifier{email}})
	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeTimeout,
		CredentialTypes: []irma.CredentialTypeIdentifier{email}})

	require.Eventually(t, func() bool { return len(portal.Reports()) == 1 }, 15*time.Second, 100*time.Millisecond)
	report := portal.Reports()[0]
	require.Equal(t, usage.ReportSchema, report.Schema)
	require.Equal(t, uint64(1), report.Sequence)
	require.False(t, report.Final)
	require.Equal(t, "test-instance", report.ServerInstance)
	require.Equal(t, []usage.DisclosureCount{
		{Day: day, Requestor: "webshop", Action: irma.ActionDisclosing, CredentialType: root.String(), Outcome: usage.OutcomeDone, Count: 1},
		{Day: day, Requestor: "webshop", Action: irma.ActionDisclosing, CredentialType: email.String(), Outcome: usage.OutcomeDone, Count: 2},
		{Day: day, Requestor: "webshop", Action: irma.ActionDisclosing, CredentialType: email.String(), Outcome: usage.OutcomeTimeout, Count: 1},
	}, report.Disclosures)
	require.Equal(t, []usage.SessionCount{
		{Day: day, Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone, Count: 2},
		{Day: day, Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeTimeout, Count: 1},
	}, report.Sessions)

	// Stopping sends a final report that closes the run, even when it holds no counts.
	reporter.Stop()
	reports := portal.Reports()
	require.Len(t, reports, 2)
	require.Equal(t, uint64(2), reports[1].Sequence)
	require.True(t, reports[1].Final)
	require.Equal(t, report.RunID, reports[1].RunID)

	// Sent reports are no longer in the outbox.
	entries, err := os.ReadDir(filepath.Join(settings.StateDir, "outbox"))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestReporterIgnoresIssuanceByDefault(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	register(t, portal, settings)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Record(usage.Event{Action: irma.ActionIssuing, Outcome: usage.OutcomeDone,
		CredentialTypes: []irma.CredentialTypeIdentifier{email}})
	reporter.Stop()

	reports := portal.Reports()
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Sessions)
}

func TestReporterKeepsReportsOfUnregisteredKey(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)

	// An unregistered key does not stop the server.
	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone,
		CredentialTypes: []irma.CredentialTypeIdentifier{email}})
	reporter.Stop()
	require.Empty(t, portal.Reports())

	entries, err := os.ReadDir(filepath.Join(settings.StateDir, "outbox"))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Once the key is registered, the next run sends the report of the earlier run too.
	register(t, portal, settings)
	reporter, err = usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Stop()

	reports := portal.Reports()
	require.Len(t, reports, 2)
	require.Equal(t, int64(1), reports[0].Sessions[0].Count)
	require.True(t, reports[0].Final)
	require.True(t, reports[1].Final)
	require.NotEqual(t, reports[0].RunID, reports[1].RunID)
	require.Equal(t, uint64(1), reports[1].Sequence)
}

func TestReporterRetriesAfterPortalError(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	register(t, portal, settings)
	portal.SetStatus(http.StatusServiceUnavailable)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionSigning, Outcome: usage.OutcomeFailed})
	time.Sleep(2500 * time.Millisecond) // at least one failed attempt
	require.Empty(t, portal.Reports())

	portal.SetStatus(0)
	reporter.Stop()
	reports := portal.Reports()
	require.Len(t, reports, 2)
	require.Equal(t, uint64(1), reports[0].Sequence)
	require.Equal(t, usage.OutcomeFailed, reports[0].Sessions[0].Outcome)
	require.Equal(t, uint64(2), reports[1].Sequence)
}

func TestReporterStartsWhenPortalIsUnreachable(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	portal.Close()

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Stop()

	entries, err := os.ReadDir(filepath.Join(settings.StateDir, "outbox"))
	require.NoError(t, err)
	require.Len(t, entries, 1, "the final report waits in the outbox")
}

func TestAccountKeyIsStable(t *testing.T) {
	dir := t.TempDir()
	key1, err := usage.LoadOrCreateKey("", dir)
	require.NoError(t, err)
	key2, err := usage.LoadOrCreateKey("", dir)
	require.NoError(t, err)
	require.Equal(t, usage.Thumbprint(key1), usage.Thumbprint(key2))

	// The key file can be used on its own, e.g. as a mounted secret.
	key3, err := usage.LoadOrCreateKey(filepath.Join(dir, "account.key"), "")
	require.NoError(t, err)
	require.Equal(t, usage.Thumbprint(key1), usage.Thumbprint(key3))

	_, err = usage.LoadOrCreateKey("", "")
	require.Error(t, err)
	_, err = usage.LoadOrCreateKey(filepath.Join(dir, "missing.key"), "")
	require.Error(t, err)
}

func TestReporterRejectsIntervalOutOfRange(t *testing.T) {
	portal := usagetest.NewPortal(t)
	for _, interval := range []time.Duration{300, 30 * time.Second, 25 * time.Hour} {
		settings := usage.Settings{PortalURL: portal.DirectoryURL(), Interval: interval, StateDir: t.TempDir()}
		_, err := usage.New(settings, logrus.New())
		require.Error(t, err, interval.String())
	}
	for _, interval := range []time.Duration{0, usage.MinInterval, usage.MaxInterval} {
		settings := usage.Settings{PortalURL: portal.DirectoryURL(), Interval: interval, StateDir: t.TempDir()}
		reporter, err := usage.New(settings, logrus.New())
		require.NoError(t, err, interval.String())
		reporter.Stop()
	}
}

func TestReporterCountsPerHost(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	register(t, portal, settings)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)

	// One server can run sessions under the hostnames of several Trusted Verifiers; the Portal
	// tells them apart by the host of each row.
	day := time.Now().UTC().Format(time.DateOnly)
	for _, host := range []string{"irma.example.com", "irma.example.org", "irma.example.org"} {
		reporter.Record(usage.Event{Requestor: "webshop", Host: host, Action: irma.ActionDisclosing,
			Outcome: usage.OutcomeDone, CredentialTypes: []irma.CredentialTypeIdentifier{email}})
	}
	reporter.Stop()

	report := portal.Reports()[0]
	require.Equal(t, []usage.SessionCount{
		{Day: day, Requestor: "webshop", Host: "irma.example.com", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone, Count: 1},
		{Day: day, Requestor: "webshop", Host: "irma.example.org", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone, Count: 2},
	}, report.Sessions)
	require.Equal(t, []usage.DisclosureCount{
		{Day: day, Requestor: "webshop", Host: "irma.example.com", Action: irma.ActionDisclosing, CredentialType: email.String(), Outcome: usage.OutcomeDone, Count: 1},
		{Day: day, Requestor: "webshop", Host: "irma.example.org", Action: irma.ActionDisclosing, CredentialType: email.String(), Outcome: usage.OutcomeDone, Count: 2},
	}, report.Disclosures)
}

func TestReporterSendsHeartbeatWithoutSessions(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	usage.SetHeartbeat(t, 2*time.Second)
	register(t, portal, settings)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)

	// Without sessions, an interval stays open until the heartbeat seals it as an empty report.
	require.Eventually(t, func() bool { return len(portal.Reports()) == 1 }, 15*time.Second, 100*time.Millisecond)
	heartbeat := portal.Reports()[0]
	require.Empty(t, heartbeat.Sessions)
	require.Empty(t, heartbeat.Disclosures)
	require.False(t, heartbeat.Final)
	require.Equal(t, int64(2), heartbeat.Heartbeat)

	reporter.Record(usage.Event{Requestor: "webshop", Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone,
		CredentialTypes: []irma.CredentialTypeIdentifier{email}})
	require.Eventually(t, func() bool { return len(portal.Reports()) == 2 }, 15*time.Second, 100*time.Millisecond)
	reporter.Stop()

	// The periods of a run follow each other without holes.
	reports := portal.Reports()
	require.Len(t, reports, 3)
	for i := 1; i < len(reports); i++ {
		require.Equal(t, uint64(i+1), reports[i].Sequence)
		require.True(t, reports[i].Period.From.Equal(reports[i-1].Period.To), "report %d", i+1)
	}
	require.Len(t, reports[1].Sessions, 1)
	require.True(t, reports[2].Final)
}

func TestHeartbeatIsAtLeastTheInterval(t *testing.T) {
	portal := usagetest.NewPortal(t)
	settings := newSettings(t, portal)
	usage.SetHeartbeat(t, time.Millisecond)
	register(t, portal, settings)

	reporter, err := usage.New(settings, logrus.New())
	require.NoError(t, err)
	reporter.Stop()
	require.Equal(t, int64(1), portal.Reports()[0].Heartbeat)
}

func TestReportsAreSealedAtIntervalBoundaries(t *testing.T) {
	at := func(s string) time.Time {
		tm, err := time.Parse(time.TimeOnly, s)
		require.NoError(t, err)
		return time.Date(2026, 11, 26, tm.Hour(), tm.Minute(), tm.Second(), 0, time.UTC)
	}
	nextDay := func(s string) time.Time { return at(s).AddDate(0, 0, 1) }
	day, fiveMinutes := 24*time.Hour, 5*time.Minute

	for _, tt := range []struct {
		name                string
		start, prev, now    time.Time
		interval, heartbeat time.Duration
		empty, due          bool
	}{
		{"sessions during the day wait for midnight",
			at("00:00:04"), at("14:23:00"), at("14:23:10"), day, day, false, false},
		{"the first tick after midnight seals the day",
			at("00:00:04"), at("23:59:58"), nextDay("00:00:08"), day, day, false, true},
		{"later ticks of the new day do not",
			nextDay("00:00:08"), nextDay("00:00:08"), nextDay("00:00:18"), day, day, false, false},
		{"a day without sessions is sealed at midnight too",
			at("00:00:04"), at("23:59:58"), nextDay("00:00:08"), day, day, true, true},
		{"the first day of a run ends at midnight",
			at("14:23:17"), at("23:59:57"), nextDay("00:00:07"), day, day, true, true},
		{"an hour ends at the whole hour",
			at("10:00:02"), at("10:59:55"), at("11:00:05"), time.Hour, time.Hour, false, true},
		{"a quiet interval stays open within the heartbeat",
			at("10:00:03"), at("10:29:58"), at("10:30:08"), fiveMinutes, time.Hour, true, false},
		{"a session after a quiet stretch waits for the next boundary",
			at("10:00:03"), at("10:32:03"), at("10:32:13"), fiveMinutes, time.Hour, false, false},
		{"and is sealed at it",
			at("10:00:03"), at("10:34:58"), at("10:35:08"), fiveMinutes, time.Hour, false, true},
		{"a quiet interval stays open while the next boundary is within the heartbeat",
			at("10:00:03"), at("10:54:58"), at("10:55:08"), fiveMinutes, time.Hour, true, false},
		{"and is sealed before it would outgrow the heartbeat",
			at("10:00:03"), at("10:59:58"), at("11:00:08"), fiveMinutes, time.Hour, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.due, usage.SealDue(tt.start, tt.prev, tt.now, tt.interval, tt.heartbeat, tt.empty))
		})
	}
}
