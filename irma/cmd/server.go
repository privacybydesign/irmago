package cmd

import irmad "github.com/privacybydesign/irmago/server/irmad/cmd"

func init() {
	irmad.RootCommand.Use = "server"
	RootCmd.AddCommand(irmad.RootCommand)
}
