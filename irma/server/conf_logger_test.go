package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// newTestLogger returns a logger writing JSON to buf, so test assertions can
// inspect the fields present on emitted log lines.
func newTestLogger(buf *bytes.Buffer) *logrus.Logger {
	l := logrus.New()
	l.SetOutput(buf)
	l.SetFormatter(&logrus.JSONFormatter{})
	l.SetLevel(logrus.InfoLevel)
	return l
}

func TestConfigurationResolveLogger(t *testing.T) {
	t.Run("neither Logger nor LoggerEntry set", func(t *testing.T) {
		conf := &Configuration{Quiet: true}
		conf.resolveLogger()
		require.NotNil(t, conf.Logger)
		require.NotNil(t, conf.LoggerEntry)
		// Logger and LoggerEntry must share the same underlying logger.
		require.Same(t, conf.Logger, conf.LoggerEntry.Logger)
		// Package-level vars are pointed at the resolved values.
		require.Same(t, conf.Logger, Logger)
		require.Same(t, conf.LoggerEntry, LoggerEntry)
	})

	t.Run("only Logger set derives an entry from it", func(t *testing.T) {
		logger := logrus.New()
		conf := &Configuration{Logger: logger}
		conf.resolveLogger()
		require.Same(t, logger, conf.Logger)
		require.NotNil(t, conf.LoggerEntry)
		require.Same(t, logger, conf.LoggerEntry.Logger)
	})

	t.Run("LoggerEntry set derives Logger from it", func(t *testing.T) {
		logger := logrus.New()
		entry := logrus.NewEntry(logger).WithField("lib", "irma")
		conf := &Configuration{LoggerEntry: entry}
		conf.resolveLogger()
		require.Same(t, entry, conf.LoggerEntry)
		require.Same(t, logger, conf.Logger)
	})

	t.Run("LoggerEntry takes precedence over Logger", func(t *testing.T) {
		entryLogger := logrus.New()
		ignoredLogger := logrus.New()
		entry := logrus.NewEntry(entryLogger)
		conf := &Configuration{Logger: ignoredLogger, LoggerEntry: entry}
		conf.resolveLogger()
		require.Same(t, entryLogger, conf.Logger)
		require.Same(t, entry, conf.LoggerEntry)
	})

	t.Run("LoggerEntry without a logger gets a default one", func(t *testing.T) {
		conf := &Configuration{Quiet: true, LoggerEntry: &logrus.Entry{}}
		conf.resolveLogger()
		require.NotNil(t, conf.Logger)
		require.Same(t, conf.Logger, conf.LoggerEntry.Logger)
	})

	t.Run("persistent fields flow through server logging", func(t *testing.T) {
		var buf bytes.Buffer
		logger := newTestLogger(&buf)
		conf := &Configuration{LoggerEntry: logrus.NewEntry(logger).WithField("lib", "irma")}
		conf.resolveLogger()

		// Any server logging done through the package-level entry must carry the
		// persistent field the caller attached.
		LoggerEntry.WithField("session", "abc").Info("session started")

		var logged map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &logged))
		require.Equal(t, "irma", logged["lib"])
		require.Equal(t, "abc", logged["session"])
		require.Equal(t, "session started", logged["msg"])
	})
}
