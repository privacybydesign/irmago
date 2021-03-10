package cmd

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sietseringers/cobra"
)

var issuerKeyverifyCmd = &cobra.Command{
	Use:   "keyverify [path]",
	Short: "Verify validity proof for an IRMA issuer keypair",
	Long: `Verify validity proof for an IRMA issuer keypair.

The keyverify command verifies proofs of validity for IRMA issuer keys. By default, it verifies the newest proof in the Proofs folder, matching it to the corresponding key in PublicKeys.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()
		counter, _ := flags.GetUint("counter")
		pubkeyfile, _ := flags.GetString("publickey")
		prooffile, _ := flags.GetString("proof")

		var err error

		// Determine path for key
		var path string
		if len(args) != 0 {
			path = args[0]
		} else {
			path, err = os.Getwd()
			if err != nil {
				die("", err)
			}
		}
		if err = common.AssertPathExists(path); err != nil {
			die("Nonexisting path specified", err)
		}

		// Determine counter if needed
		if !flags.Changed("counter") {
			counter = uint(lastProofIndex(path))
		}

		// Fill in pubkey if needed
		if pubkeyfile == "" {
			pubkeyfile = filepath.Join(path, "PublicKeys", strconv.Itoa(int(counter))+".xml")
		}

		// Fill in proof if needed
		if prooffile == "" {
			prooffile = filepath.Join(path, "Proofs", strconv.Itoa(int(counter))+".json.gz")
		}

		// Try to read public key
		pk, err := gabi.NewPublicKeyFromFile(pubkeyfile)
		if err != nil {
			die("Error reading public key", err)
		}

		// Start log follower
		follower := startLogFollower()
		defer func() {
			follower.quitEvents <- quitMessage{}
			<-follower.finished
		}()

		// Try to read proof
		follower.StepStart("Reading proofdata", 0)
		proofFile, err := os.Open(prooffile)
		if err != nil {
			follower.StepDone()
			die("Error opening proof", err)
		}
		defer closeCloser(proofFile)
		proofGzip, err := gzip.NewReader(proofFile)
		if err != nil {
			follower.StepDone()
			die("Error reading proof data", err)
		}
		defer closeCloser(proofGzip)
		proofDecoder := json.NewDecoder(proofGzip)
		var proof keyproof.ValidKeyProof
		err = proofDecoder.Decode(&proof)
		if err != nil {
			follower.StepDone()
			die("Error reading proof data", err)
		}
		follower.StepDone()

		// Construct proof structure
		s := keyproof.NewValidKeyProofStructure(pk.N, pk.Z, pk.S, pk.R)

		// And use it to validate the proof
		if !s.VerifyProof(proof) {
			die("Proof is invalid!", nil)
		} else {
			follower.finalEvents <- setFinalMessage{"Proof is valid"}
		}
	},
}

func closeCloser(c io.Closer) {
	if err := c.Close(); err != nil {
		die("", err)
	}
}

func lastProofIndex(path string) (counter int) {
	matches, _ := filepath.Glob(filepath.Join(path, "Proofs", "*.json.gz"))
	for _, match := range matches {
		filename := filepath.Base(match)
		c, err := strconv.Atoi(filename[:len(filename)-8])
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		if c > counter {
			counter = c
		}
	}
	return
}

func init() {
	issuerCmd.AddCommand(issuerKeyverifyCmd)

	issuerKeyverifyCmd.Flags().StringP("publickey", "p", "", `File of public key to verify (default "PublicKeys/$index.xml")`)
	issuerKeyverifyCmd.Flags().StringP("proof", "o", "", `File of proof to verify (default "Proofs/$counter.json.gz")`)
	issuerKeyverifyCmd.Flags().UintP("counter", "c", 0, "Counter of key to verify (default to latest with proof)")
}
