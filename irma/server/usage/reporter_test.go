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
	for _, interval := range []time.Duration{300, 30 * time.Second, 7 * time.Hour} {
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
	require.GreaterOrEqual(t, heartbeat.Period.To.Sub(heartbeat.Period.From), 2*time.Second)

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
