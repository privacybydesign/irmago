package eudicli

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/spf13/cobra"
)

var loteShowCmd = &cobra.Command{
	Use:   "show <list.jws>",
	Short: "Print a signed LoTE in readable form",
	Long: `Print a signed List of Trusted Entities in readable form.

The document is verified first — there is no way to read a LoTE in this codebase
without its signature having held — so this also answers "is this file a valid
list". Without --anchor the chain is not checked; see verify.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		anchorPath, _ := cmd.Flags().GetString("anchor")

		signed, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		anchors, _, err := verifyAnchors(anchorPath, signed)
		if err != nil {
			return err
		}
		list, err := lote.VerifySigned(signed, anchors)
		if err != nil {
			return err
		}

		out := &strings.Builder{}
		writeScheme(out, list.SchemeInformation)
		for _, entity := range list.Entities {
			writeEntity(out, entity)
		}
		fmt.Print(out.String())
		return nil
	},
}

func init() {
	loteCmd.AddCommand(loteShowCmd)

	loteShowCmd.Flags().String("anchor", "", "PEM trust anchor to check the chain against")
}

func writeScheme(out *strings.Builder, scheme lote.SchemeInformation) {
	fmt.Fprintf(out, "%s\n", scheme.Identity())
	fmt.Fprintf(out, "  type            %s\n", scheme.LoTEType)
	fmt.Fprintf(out, "  operator        %s (%s)\n", translated(scheme.SchemeOperatorName), scheme.SchemeTerritory)
	fmt.Fprintf(out, "  sequence        %d\n", scheme.SequenceNumber)
	fmt.Fprintf(out, "  issued          %s\n", scheme.ListIssueDateTime.Format(time.RFC3339))

	// The one line an operator is most likely to be reading this for, so the
	// remaining window is spelled out rather than left as arithmetic.
	remaining := time.Until(scheme.NextUpdate).Truncate(time.Minute)
	currency := fmt.Sprintf("in %s", remaining)
	if remaining <= 0 {
		currency = "EXPIRED"
	}
	fmt.Fprintf(out, "  next update     %s (%s)\n", scheme.NextUpdate.Format(time.RFC3339), currency)
}

func writeEntity(out *strings.Builder, entity lote.Entity) {
	information := entity.Information
	fmt.Fprintf(out, "\n%s\n", translated(information.Name))
	if id := information.OrganizationIdentifier(); id != "" {
		fmt.Fprintf(out, "  organization    %s\n", id)
	}
	if logo := information.LogoURI(); logo != "" {
		fmt.Fprintf(out, "  logo            %s\n", logo)
	}

	for _, service := range entity.Services {
		writeService(out, service.Information)
	}
}

func writeService(out *strings.Builder, service lote.ServiceInformation) {
	role := "unknown"
	if mapped, ok := service.Type.Role(); ok {
		role = string(mapped)
	}
	// Through IsGranted, so the absent-means-granted rule is read the way the
	// wallet reads it: Yivi's own list omits ServiceStatus entirely, and
	// comparing against the granted URI directly would label every entry of a
	// conformant list NOT GRANTED.
	status := "NOT GRANTED"
	if service.IsGranted() {
		status = "granted"
	}

	fmt.Fprintf(out, "  %-8s %-11s %s\n", role, status, translated(service.Name))
	for _, line := range identityLines(service.DigitalIdentity) {
		fmt.Fprintf(out, "      %s\n", line)
	}
	if markings := service.Markings(); len(markings) > 0 {
		fmt.Fprintf(out, "      markings: %s\n", strings.Join(markings, ", "))
	}
}

// identityLines renders what a service is recognized by, one line per identity.
func identityLines(identity lote.DigitalIdentity) []string {
	var lines []string
	for _, did := range identity.OtherIds {
		lines = append(lines, "did "+did)
	}
	for _, ski := range identity.X509SKIs {
		lines = append(lines, "ski "+hexBytes(ski))
	}
	for _, certificate := range identity.X509Certificates {
		lines = append(lines, fmt.Sprintf("cert %d bytes of DER", len(certificate.Val)))
	}
	for _, subject := range identity.X509SubjectNames {
		// Shown but flagged: the wallet does not match on subject names, so an
		// entry relying on one grants nothing.
		lines = append(lines, "subject "+subject+" (not matched on)")
	}
	slices.Sort(lines)
	return lines
}

func hexBytes(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
