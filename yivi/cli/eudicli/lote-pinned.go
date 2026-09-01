package eudicli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/spf13/cobra"
)

var lotePinnedCmd = &cobra.Command{
	Use:   "pinned",
	Short: "List the trust anchors compiled into this binary",
	Long: `List the trust anchors compiled into this binary: the CAs a wallet built from
it trusts before it has fetched any list, per pool and environment.

These are the floor the anchor list adds to and never removes. They are meant to
be generated from the same curation the anchor list is built from, so a curation
repository's CI can run this against the pinned irmago release and diff the result
with its own CA services: a mismatch is a Yivi CA rotated in one place and not the
other.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		asJson, _ := cmd.Flags().GetBool("json")

		anchors, err := pinnedAnchors()
		if err != nil {
			return err
		}

		if asJson {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(anchors)
		}
		for _, anchor := range anchors {
			fmt.Printf("%-10s %-11s %s\n", anchor.Environment, anchor.Pool, anchor.Subject)
			fmt.Printf("           ski %s\n", anchor.SKI)
			fmt.Printf("           sha256 %s\n", anchor.SHA256)
			fmt.Printf("           confers %s, valid until %s\n", anchor.Confers, anchor.NotAfter.Format(time.RFC3339))
		}
		return nil
	},
}

func init() {
	loteCmd.AddCommand(lotePinnedCmd)
	lotePinnedCmd.Flags().Bool("json", false, "print the anchors as JSON, for a CI diff")
}

// pinnedAnchor is one compiled-in anchor as the curation would describe it.
type pinnedAnchor struct {
	Environment string                  `json:"environment"`
	Pool        string                  `json:"pool"`
	Subject     string                  `json:"subject"`
	SKI         string                  `json:"ski"`
	SHA256      string                  `json:"sha256"`
	NotAfter    time.Time               `json:"not_after"`
	Confers     clientmodels.TrustLevel `json:"confers"`
}

// pinnedAnchors reads the compiled-in anchor constants the way the wallet installs
// them: the first certificate of each chain is the anchor, at the level the wallet
// records for it. The trust-list anchors are listed too, level-less, since nothing
// classifies against them.
func pinnedAnchors() ([]pinnedAnchor, error) {
	constants := []struct {
		environment, pool, pem string
		confers                clientmodels.TrustLevel
	}{
		{"production", "issuers", eudi.Production_Yivi_IssuerTrustAnchor, clientmodels.TrustLevel_High},
		{"production", "verifiers", eudi.Production_Yivi_VerifierTrustAnchor, clientmodels.TrustLevel_High},
		{"production", "trustlists", eudi.Production_Yivi_TrustListTrustAnchor, clientmodels.TrustLevel_Unevaluated},
		{"staging", "issuers", eudi.Staging_Yivi_IssuerTrustAnchor, clientmodels.TrustLevel_High},
		{"staging", "verifiers", eudi.Staging_Yivi_VerifierTrustAnchor, clientmodels.TrustLevel_High},
		{"staging", "trustlists", eudi.Staging_Yivi_TrustListTrustAnchor, clientmodels.TrustLevel_Unevaluated},
	}

	var anchors []pinnedAnchor
	for _, constant := range constants {
		if constant.pem == "" {
			continue
		}
		chain, err := utils.ParsePemCertificateChain([]byte(constant.pem))
		if err != nil {
			return nil, fmt.Errorf("%s %s anchor: %w", constant.environment, constant.pool, err)
		}
		if len(chain) == 0 {
			continue
		}
		anchor := chain[0]
		digest := sha256.Sum256(anchor.Raw)
		anchors = append(anchors, pinnedAnchor{
			Environment: constant.environment,
			Pool:        constant.pool,
			Subject:     anchor.Subject.ToRDNSequence().String(),
			SKI:         hex.EncodeToString(anchor.SubjectKeyId),
			SHA256:      hex.EncodeToString(digest[:]),
			NotAfter:    anchor.NotAfter,
			Confers:     constant.confers,
		})
	}
	return anchors, nil
}
