package clihelpers

import (
	"os"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
)

func Die(message string, err error, logger *logrus.Logger) {
	var m string
	if message != "" {
		m = message
	}
	if err != nil {
		if message != "" {
			m += ": "
		}
		if e, ok := err.(*errors.Error); ok && logger.IsLevelEnabled(logrus.DebugLevel) {
			m += e.ErrorStack()
		} else {
			m += err.Error()
		}
	}

	logger.Error(m)
	os.Exit(1)
}
