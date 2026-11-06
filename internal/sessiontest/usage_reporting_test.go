package sessiontest

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/privacybydesign/irmago/irma/server/usage"
	"github.com/privacybydesign/irmago/irma/server/usage/usagetest"
	"github.com/stretchr/testify/require"
)

// usageReportingSettings points usage reporting at the fake Portal and registers its key there.
func usageReportingSettings(t *testing.T, portal *usagetest.Portal) *usage.Settings {
	settings := &usage.Settings{
		PortalURL:      portal.DirectoryURL(),
		Interval:       time.Hour, // only the final report on Stop() is sent
		StateDir:       t.TempDir(),
		ServerInstance: "sessiontest",
	}
	key, err := usage.LoadOrCreateKey("", settings.StateDir)
	require.NoError(t, err)
	portal.Register(usage.Thumbprint(key))
	return settings
}

// sumUsage adds up the counts over all reports the Portal received.
func sumUsage(reports []*usage.Report) (map[usage.DisclosureCount]int64, map[usage.SessionCount]int64) {
	disclosures, sessions := map[usage.DisclosureCount]int64{}, map[usage.SessionCount]int64{}
	for _, r := range reports {
		for _, d := range r.Disclosures {
			n := d.Count
			d.Count, d.Day = 0, ""
			disclosures[d] += n
		}
		for _, s := range r.Sessions {
			n := s.Count
			s.Count, s.Day = 0, ""
			sessions[s] += n
		}
	}
	return disclosures, sessions
}

func TestUsageReporting(t *testing.T) {
	mr, cert := startRedis(t, true)
	defer mr.Close()

	stores := map[string]func() *server.Configuration{
		"memory": IrmaServerConfiguration,
		"redis":  redisConfigDecorator(mr, cert, "", IrmaServerConfiguration),
	}
	for name, configure := range stores {
		t.Run(name, func(t *testing.T) {
			portal := usagetest.NewPortal(t)
			conf := configure()
			conf.UsageReporting = usageReportingSettings(t, portal)
			irmaServer := StartIrmaServer(t, conf)

			studentID := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
			studentCard := studentID.CredentialTypeIdentifier().String()

			// Two disclosures of the same credential type and one signature.
			doSession(t, getDisclosureRequest(studentID), nil, irmaServer, nil, nil, nil, nil)
			doSession(t, getDisclosureRequest(studentID), nil, irmaServer, nil, nil, nil, nil)
			doSession(t, getSigningRequest(studentID), nil, irmaServer, nil, nil, nil, nil)

			// A session the requestor cancels counts the credential type it asked for.
			_, token, _, err := irmaServer.irma.StartSession(getDisclosureRequest(studentID), nil, "")
			require.NoError(t, err)
			require.NoError(t, irmaServer.irma.CancelSession(token))

			// Stopping the server sends the final report.
			irmaServer.Stop()

			reports := portal.Reports()
			require.NotEmpty(t, reports)
			require.True(t, reports[len(reports)-1].Final)

			disclosures, sessions := sumUsage(reports)
			require.Equal(t, map[usage.DisclosureCount]int64{
				{Action: irma.ActionDisclosing, CredentialType: studentCard, Outcome: usage.OutcomeDone}:      2,
				{Action: irma.ActionSigning, CredentialType: studentCard, Outcome: usage.OutcomeDone}:         1,
				{Action: irma.ActionDisclosing, CredentialType: studentCard, Outcome: usage.OutcomeCancelled}: 1,
			}, disclosures)
			require.Equal(t, map[usage.SessionCount]int64{
				{Action: irma.ActionDisclosing, Outcome: usage.OutcomeDone}:      2,
				{Action: irma.ActionSigning, Outcome: usage.OutcomeDone}:         1,
				{Action: irma.ActionDisclosing, Outcome: usage.OutcomeCancelled}: 1,
			}, sessions)
		})
	}
}

func TestUsageReportingPerRequestor(t *testing.T) {
	portal := usagetest.NewPortal(t)
	conf := RequestorServerConfiguration()
	conf.UsageReporting = usageReportingSettings(t, portal)
	requestorServer := StartRequestorServer(t, conf)

	studentID := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	doSession(t, getDisclosureRequest(studentID), nil, nil, requestorServer, nil, nil, nil)
	requestorServer.Stop()

	disclosures, _ := sumUsage(portal.Reports())
	require.Equal(t, map[usage.DisclosureCount]int64{
		{Requestor: "requestor1", Action: irma.ActionDisclosing,
			CredentialType: studentID.CredentialTypeIdentifier().String(), Outcome: usage.OutcomeDone}: 1,
	}, disclosures)
}

func TestUsageReportingOffByDefault(t *testing.T) {
	// Outside production mode, and in production mode without any usage reporting configuration,
	// the server behaves as before: nothing is counted or sent.
	for _, production := range []bool{false, true} {
		conf := RequestorServerConfiguration()
		conf.Production = production
		conf.DisableTLS = true
		require.NoError(t, conf.Check())
		require.IsType(t, usage.NoopCounter{}, conf.UsageCounter)
	}
}
