package eudicli

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
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
			args[0], scheme.Identity(), scheme.SequenceNumber, len(list.Entities))

		// Reported, not enforced: an expired document is still a genuine one, and
		// signing a list whose window has already closed is a mistake worth
		// naming rather than a verification failure.
		if scheme.NextUpdate.Before(time.Now()) {
			return fmt.Errorf("this document is already past its NextUpdate (%s)",
				scheme.NextUpdate.Format(time.RFC3339))
		}

		if against == "" {
			return nil
		}
		return compareToPublished(against, anchors, scheme.SequenceNumber)
	},
}

func init() {
	loteCmd.AddCommand(loteVerifyCmd)

	loteVerifyCmd.Flags().String("anchor", "", "PEM trust anchor to check the chain against, as the wallet will")
	loteVerifyCmd.Flags().String("against", "",
		"URL of the currently published list; fails unless this document's sequence number is higher")
}

// compareToPublished fetches the live list and refuses to let a document through
// that would not advance it.
func compareToPublished(url string, anchors eudi_jwt.X509VerificationContext, sequenceNumber uint64) error {
	published, err := fetchPublished(url)
	if err != nil {
		// A first publish has nothing to compare against, and so does an outage —
		// which are not the same thing, so this reports rather than passing.
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

func fetchPublished(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("non-2xx response: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5<<20))
}

// verifyAnchors builds the pool for `verify`. With no --anchor the document's own
// signing certificate stands in as its own root, which checks everything except
// whether a wallet would trust the chain.
func verifyAnchors(anchorPath string, signed []byte) (eudi_jwt.X509VerificationContext, bool, error) {
	pool := x509.NewCertPool()
	checksChain := false

	if anchorPath != "" {
		anchors, err := readCertificateChain(anchorPath)
		if err != nil {
			return nil, false, err
		}
		for _, anchor := range anchors {
			pool.AddCert(anchor)
		}
		checksChain = true
	} else {
		leaf, err := signingCertificateOf(signed)
		if err != nil {
			return nil, false, err
		}
		pool.AddCert(leaf)
	}

	return &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}}, checksChain, nil
}
