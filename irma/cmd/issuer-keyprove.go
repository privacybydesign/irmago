package cmd

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

var issuerKeyproveCmd = &cobra.Command{
	Use:   "keyprove [<path>]",
	Short: "Generate validity proof for an IRMA issuer keypair",
	Long: `Generate validity proof for an IRMA issuer keypair.

The keyprove command generates a proof that an issuer private/public keypair was generated
correctly. By default, it acts on the newest keypair in the <path>/PrivateKeys and <path>/PublicKeys
folders, and then stores the proof in the <path>/Proofs folder. If not specified, <path> is taken to
be the current working directory.

For 2048 bit keys, keyprove will output a proof of about 700 MB. On machines of 2 - 3 GHz generating
will take some 5 - 15 minutes, during which CPU usage will be 100% most of the time. Up to 8 GB RAM
may be used.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()
		counter, _ := flags.GetUint("counter")
		pubkeyfile, _ := flags.GetString("publickey")
		privkeyfile, _ := flags.GetString("privatekey")
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
			counter = uint(lastPrivateKeyIndex(path))
		}

		// Fill in pubkey if needed
		if pubkeyfile == "" {
			pubkeyfile = filepath.Join(path, "PublicKeys", strconv.Itoa(int(counter))+".xml")
		}

		// Fill in privkey if needed
		if privkeyfile == "" {
			privkeyfile = filepath.Join(path, "PrivateKeys", strconv.Itoa(int(counter))+".xml")
		}

		// Try to read public key
		pk, err := gabikeys.NewPublicKeyFromFile(pubkeyfile)
		if err != nil {
			die("Could not read public key", err)
		}

		// Try to read private key
		sk, err := gabikeys.NewPrivateKeyFromFile(privkeyfile, false)
		if err != nil {
			die("Could not read private key", err)
		}

		// Validate that they match
		if pk.N.Cmp(new(big.Int).Mul(sk.P, sk.Q)) != 0 {
			die("Private and public key do not match", nil)
		}

		// Validate that the key is eligble to proving
		if !keyproof.CanProve(sk.PPrime, sk.QPrime) {
			die("Private key not eligible to proving", nil)
		}

		// Prepare storage for proof if needed
		if prooffile == "" {
			proofpath := filepath.Join(path, "Proofs")
			if err = common.EnsureDirectoryExists(proofpath); err != nil {
				die("Failed to create"+proofpath, err)
			}
			prooffile = filepath.Join(proofpath, strconv.Itoa(int(counter))+".json.gz")
		}

		// Open proof file for writing
		proofOut, err := os.Create(prooffile)
		if err != nil {
			die("Error opening proof file for writing", err)
		}
		defer closeCloser(proofOut)

		// Wrap it for gzip compression
		proofWriter := gzip.NewWriter(proofOut)
		defer closeCloser(proofWriter)

		// Start log follower
		follower := startLogFollower()
		defer func() {
			follower.quitEvents <- quitMessage{}
			<-follower.finished
		}()

		// Build the proof
		bases := append([]*big.Int{pk.Z, pk.S})
		if pk.G != nil {
			bases = append(bases, pk.G)
		}
		if pk.H != nil {
			bases = append(bases, pk.H)
		}
		s := keyproof.NewValidKeyProofStructure(pk.N, append(bases, pk.R...))
		proof := s.BuildProof(sk.PPrime, sk.QPrime)

		// And write it to file
		follower.StepStart("Writing proof", 0)
		proofEncoder := json.NewEncoder(proofWriter)
		err = proofEncoder.Encode(proof)
		follower.StepDone()
		if err != nil {
			die("Could not write proof", err)
		}
	},
}

func init() {
	issuerCmd.AddCommand(issuerKeyproveCmd)

	issuerKeyproveCmd.Flags().StringP("privatekey", "s", "", `File to get private key from (default "<path>/PrivateKeys/$counter.xml")`)
	issuerKeyproveCmd.Flags().StringP("publickey", "p", "", `File to get public key from (default "<path>/PublicKeys/$counter.xml")`)
	issuerKeyproveCmd.Flags().StringP("proof", "o", "", `File to write proof to (default "<path>/Proofs/$index.json.gz")`)
	issuerKeyproveCmd.Flags().UintP("counter", "c", 0, "Counter of key to prove (defaults to latest)")
}

func lastPrivateKeyIndex(path string) (counter int) {
	matches, _ := filepath.Glob(filepath.Join(path, "PrivateKeys", "*.xml"))
	for _, match := range matches {
		filename := filepath.Base(match)
		c, err := strconv.Atoi(filename[:len(filename)-4])
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

type (
	stepStartMessage struct {
		desc          string
		intermediates int
	}
	stepDoneMessage struct{}
	tickMessage     struct{}
	quitMessage     struct{}
	finishMessage   struct{}
	setFinalMessage struct {
		message string
	}

	logFollower struct {
		stepStartEvents chan<- stepStartMessage
		stepDoneEvents  chan<- stepDoneMessage
		tickEvents      chan<- tickMessage
		quitEvents      chan<- quitMessage
		finalEvents     chan<- setFinalMessage
		finished        <-chan finishMessage
	}
)

func (l *logFollower) StepStart(desc string, intermediates int) {
	l.stepStartEvents <- stepStartMessage{desc, intermediates}
}

func (l *logFollower) StepDone() {
	l.stepDoneEvents <- stepDoneMessage{}
}

func (l *logFollower) Tick() {
	l.tickEvents <- tickMessage{}
}

func printProofStatus(status string, count, limit int, done bool) {
	var tail string
	if done {
		tail = "done"
	} else if limit > 0 {
		tail = fmt.Sprintf("%v/%v", count, limit)
	} else {
		tail = ""
	}

	tlen := len(tail)
	if tlen == 0 {
		tlen = 4
	}

	fmt.Printf("\r%s%s%s", status, strings.Repeat(".", 60-len(status)-tlen), tail)
}

func startLogFollower() *logFollower {
	var result = new(logFollower)

	starts := make(chan stepStartMessage)
	dones := make(chan stepDoneMessage)
	ticks := make(chan tickMessage)
	quit := make(chan quitMessage)
	finished := make(chan finishMessage)
	finalmessage := make(chan setFinalMessage)

	result.stepStartEvents = starts
	result.stepDoneEvents = dones
	result.tickEvents = ticks
	result.quitEvents = quit
	result.finished = finished
	result.finalEvents = finalmessage

	go func() {
		doneMissing := 0
		curStatus := ""
		curCount := 0
		curLimit := 0
		curDone := true
		finalMessage := ""
		ticker := time.NewTicker(time.Second / 4)
		defer ticker.Stop()

		for {
			select {
			case <-ticks:
				curCount++
			case <-dones:
				if doneMissing > 0 {
					doneMissing--
					continue // Swallow quietly
				} else {
					curDone = true
					printProofStatus(curStatus, curCount, curLimit, true)
					fmt.Printf("\n")
				}
			case stepstart := <-starts:
				if !curDone {
					printProofStatus(curStatus, curCount, curLimit, true)
					fmt.Printf("\n")
					doneMissing++
				}
				curDone = false
				curCount = 0
				curLimit = stepstart.intermediates
				curStatus = stepstart.desc
			case messageevent := <-finalmessage:
				finalMessage = messageevent.message
			case <-quit:
				if finalMessage != "" {
					fmt.Printf("%s\n", finalMessage)
				}
				finished <- finishMessage{}
				return
			case <-ticker.C:
				if !curDone {
					printProofStatus(curStatus, curCount, curLimit, false)
				}
			}
		}
	}()

	keyproof.Follower = result

	return result
}
