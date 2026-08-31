package mdoc_dcql

import (
	"os"
	"testing"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/sirupsen/logrus"
)

// Mirrors eudi_sdjwt_dcql's TestMain. Without it eudi.Logger is nil here, and
// any test reaching a code path that logs -- claimDisplayName's bare-element
// warning is the first one to -- panics inside logrus rather than failing.
func TestMain(m *testing.M) {
	if eudi.Logger == nil {
		eudi.Logger = logrus.StandardLogger()
	}
	os.Exit(m.Run())
}
