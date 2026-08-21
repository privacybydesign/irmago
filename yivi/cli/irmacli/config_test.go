package irmacli

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestCommandHasProductionMode is a regression test for the keyshare tasks
// command logging a confusing "mode=development" line on startup. Tasks have
// no development/production distinction, so they must not report a mode.
func TestCommandHasProductionMode(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		// Regression: keyshare tasks must NOT log a mode.
		{"keyshare tasks", keyshareTaskCmd, false},

		// Commands that do have a development/production distinction.
		{"irma server", serverCmd, true},
		{"keyshare server", keyshareServerCmd, true},
		{"myirma server", myirmaServerCmd, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandHasProductionMode(tt.cmd); got != tt.want {
				t.Errorf("commandHasProductionMode(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
