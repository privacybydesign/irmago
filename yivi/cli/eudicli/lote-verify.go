package eudicli

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/spf13/cobra"
)

var loteVerifyCmd = &cobra.Command{
	Use:   "verify <list.jws>",
	Short: "Re-check a signed LoTE, and optionally against the published one",
	Long: `Re-check a signed List of Trusted Entities with the wallet's own verifier.

With --anchor the chain is validated as the wallet will validate it. Without it
the signature, the typ guard and the document are checked but the chain is not.

With --against, the currently published list is fetched and this document's
sequence number compared to it. The check is stricter than the wallet's: the
wallet refuses only a *lower* number, so an unchanged one publishes fine and
quietly flattens replay protection. This is the release gate that makes a missed
bump loud, so it fails on equal too.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		anchorPath, _ := cmd.Flags().GetString("anchor")
		against, _ := cmd.Flags().GetString("against")

		signed, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}

		anchors, checksChain, err := verifyAnchors(anchorPath, signed)
		if err != nil {
			return err
		}
		list, err := lote.VerifySigned(signed, anchors)
		if err != nil {
			return err
		}
		if !checksChain {
			Logger.Warn("no --anchor given: the chain was not checked")
		}

		scheme := list.SchemeInformation
		Logger.Infof("%s verifies: %q, sequence number %d, %d entities",
			args[0], scheme.SchemeName["en"], scheme.SequenceNumber, len(list.Entities))

		// Reported, not enforced: an expired document is still a genuine one.
		if scheme.NextUpdate.Before(time.Now()) {
			return fmt.Errorf("this document is already past its NextUpdate (%s)",
				scheme.NextUpdate.Format(time.RFC3339))
		}

		if against == "" {
			return nil
		}
		return compareToPublished(cmd.Context(), against, anchors, scheme.SequenceNumber)
	},
}

func init() {
	loteCmd.AddCommand(loteVerifyCmd)

	loteVerifyCmd.Flags().String("anchor", "", "PEM trust anchor to check the chain against, as the wallet will")
	loteVerifyCmd.Flags().String("against", "",
		"URL of the currently published list; fails unless this document's sequence number is higher")
}

// compareToPublished refuses a document that would not advance the live list.
func compareToPublished(ctx context.Context, url string, anchors eudi_jwt.X509VerificationContext, sequenceNumber uint64) error {
	// Through the wallet's own fetcher, so the release gate reads the published
	// list under the same cap, timeout and status rules.
	published, err := lote.Fetch(ctx, nil, url)
	if err != nil {
		// A first publish and an outage look alike here, so this reports rather
		// than passing.
		return fmt.Errorf("fetch the published list at %s: %w", url, err)
	}

	live, err := lote.VerifySigned(published, anchors)
	if err != nil {
		return fmt.Errorf("the published list does not verify: %w", err)
	}

	if sequenceNumber <= live.SchemeInformation.SequenceNumber {
		return fmt.Errorf(
			"sequence number %d does not advance the published %d: bump sequence_number in %s",
			sequenceNumber, live.SchemeInformation.SequenceNumber, schemeFileName)
	}
	Logger.Infof("advances the published list (%d -> %d)",
		live.SchemeInformation.SequenceNumber, sequenceNumber)
	return nil
}

// verifyAnchors builds the pool for `verify`, differing from `sign` only in where
// the fallback leaf comes from: out of the document's own `x5c` header. The
// no-anchor policy itself lives in verificationAnchors.
func verifyAnchors(anchorPath string, signed []byte) (eudi_jwt.X509VerificationContext, bool, error) {
	// Only needed as a stand-in root.
	var leaf *x509.Certificate
	if anchorPath == "" {
		var err error
		if leaf, err = signingCertificateOf(signed); err != nil {
			return nil, false, err
		}
	}
	return verificationAnchors(anchorPath, leaf)
}
