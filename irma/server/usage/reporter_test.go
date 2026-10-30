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
