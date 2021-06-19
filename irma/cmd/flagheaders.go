package cmd

import (
	"regexp"
	"strings"
)

// headerFlagsTemplate is copied from cobra.Command.UsageTemplate, modified to include an invocation
// of insertHeaders on the flags, which intersperses the flags with headers.
var headerFlagsTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces | insertHeaders .CommandPath}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

var flagHeaders = map[string]map[string]string{}

func insertHeaders(cmdPath string, flags string) string {
	headers := flagHeaders[cmdPath]
	if len(headers) == 0 {
		return flags
	}

	in := strings.Split(flags, "\n")
	out := make([]string, 0, len(in)+len(headers))
	r := regexp.MustCompile(`^\s+(-\w, )?--([^ ]*)`)

	for _, line := range in {
		matches := r.FindStringSubmatch(line)
		header := headers[matches[2]]
		if header != "" {
			out = append(out, "\n"+header)
		}
		out = append(out, line)
	}

	return strings.Join(out, "\n")
}
