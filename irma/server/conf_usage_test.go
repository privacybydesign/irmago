package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server/usage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// usageConf is a production configuration whose schemes include the non-demo requestor scheme
// test-requestors, which lists the requestor test-requestors.test-requestor under "localhost".
func usageConf(t *testing.T, serverURL string) *Configuration {
	irmaconf, err := irma.NewConfiguration(filepath.Join(test.FindTestdataFolder(t), "irma_configuration"),
		irma.ConfigurationOptions{ReadOnly: true})
	require.NoError(t, err)
	require.NoError(t, irmaconf.ParseFolder())

	logger := logrus.New()
	logger.Level = logrus.FatalLevel
	return &Configuration{
		IrmaConfiguration: irmaconf,
		Logger:            logger,
		Production:        true,
		URL:               serverURL,
	}
}

func TestUsageReportingRequiredForTrustedVerifier(t *testing.T) {
	conf := usageConf(t, "https://localhost:8088/irma/")
	err := conf.verifyUsageReporting()
	require.ErrorContains(t, err, "required on a server of a Trusted Verifier: localhost (test-requestors.test-requestor)")
	require.Nil(t, conf.UsageCounter)

	conf = usageConf(t, "https://localhost/")
	conf.UsageReporting = &usage.Settings{Disabled: true}
	require.ErrorContains(t, conf.verifyUsageReporting(), "cannot be disabled on a server of a Trusted Verifier")
}

func TestUsageReportingRequiredForTrustedVerifierSessionHost(t *testing.T) {
	// The server's own URL is no Trusted Verifier, but a requestor may put one in the QR.
	conf := usageConf(t, "https://irma.example.com/")
	conf.SessionHosts = []string{"irma.example.org", "localhost:8443"}
	require.ErrorContains(t, conf.verifyUsageReporting(), "localhost (test-requestors.test-requestor)")
}

func TestUsageReportingOptionalForOtherServers(t *testing.T) {
	notRequired := map[string]func(conf *Configuration){
		"other host":                func(conf *Configuration) { conf.URL = "https://irma.example.com/" },
		"wildcard session host":     func(conf *Configuration) { conf.URL = "https://irma.example.com/"; conf.SessionHosts = []string{"*"} },
		"development mode":          func(conf *Configuration) { conf.Production = false },
		"requestor no longer valid": func(conf *Configuration) { expire(conf, "localhost") },
		"demo requestor scheme": func(conf *Configuration) {
			conf.IrmaConfiguration.RequestorSchemes[irma.NewRequestorSchemeIdentifier("test-requestors")].Demo = true
		},
	}
	for name, change := range notRequired {
		t.Run(name, func(t *testing.T) {
			conf := usageConf(t, "https://localhost/")
			change(conf)
			require.NoError(t, conf.verifyUsageReporting())
			require.IsType(t, usage.NoopCounter{}, conf.UsageCounter)
		})
	}
}

func TestUsageReportingDisabledWithOwnCounter(t *testing.T) {
	// Yivi's own services provide a counter instead of disabling reporting.
	conf := usageConf(t, "https://localhost/")
	conf.UsageCounter = usage.NoopCounter{}
	require.NoError(t, conf.verifyUsageReporting())
}

func expire(conf *Configuration, hostname string) {
	past := irma.Timestamp(time.Now().Add(-time.Hour))
	conf.IrmaConfiguration.Requestors[hostname].ValidUntil = &past
}
