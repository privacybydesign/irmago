package sessiontest

import (
	"os"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server/usage"
)

// TestUsageReportingE2E runs IRMA sessions against a production-mode requestor server that
// reports to a real Yivi Portal. It runs only when USAGE_E2E_PORTAL_URL (the usage directory URL)
// and USAGE_E2E_STATE_DIR (holding an account key registered in that Portal) are set; the e2e
// script sets both and checks the Portal's records afterwards.
func TestUsageReportingE2E(t *testing.T) {
	portalURL, stateDir := os.Getenv("USAGE_E2E_PORTAL_URL"), os.Getenv("USAGE_E2E_STATE_DIR")
	if portalURL == "" || stateDir == "" {
		t.Skip("USAGE_E2E_PORTAL_URL and USAGE_E2E_STATE_DIR are not set")
	}

	conf := RequestorServerConfiguration()
	conf.Production = true
	conf.DisableTLS = true
	conf.UsageReporting = &usage.Settings{
		PortalURL:      portalURL,
		StateDir:       stateDir,
		Interval:       2 * time.Second,
		ServerInstance: "e2e-sessiontest",
	}
	requestorServer := StartRequestorServer(t, conf)

	studentID := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	doSession(t, getDisclosureRequest(studentID), nil, nil, requestorServer, nil, nil, nil)

	// Let at least one interval pass, so a delta report is sent before the final one.
	time.Sleep(5 * time.Second)

	doSession(t, getDisclosureRequest(studentID), nil, nil, requestorServer, nil, nil, nil)
	doSession(t, getSigningRequest(studentID), nil, nil, requestorServer, nil, nil, nil)

	// Stopping sends the final report of this run.
	requestorServer.Stop()
}
