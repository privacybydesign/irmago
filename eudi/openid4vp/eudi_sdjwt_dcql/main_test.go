package eudi_sdjwt_dcql

import (
	"os"
	"testing"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	if eudi.Logger == nil {
		eudi.Logger = logrus.StandardLogger()
	}
	os.Exit(m.Run())
}
