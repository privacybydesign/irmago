package main

import (
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
)

var RunCommand = &cobra.Command{
	Use:   "run",
	Short: "Run server (same as specifying no command)",
	Run:   RootCommand.Run,
}

func init() {
	RootCommand.AddCommand(RunCommand)

	if err := setFlags(RunCommand); err != nil {
		die(errors.WrapPrefix(err, "Failed to attach flags to "+RunCommand.Name()+" command", 0))
	}
}
