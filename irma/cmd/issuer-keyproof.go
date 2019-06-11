package cmd

import (
	"fmt"
	"os"
	"time"
	"path/filepath"
	"strconv"
	"compress/gzip"
	"encoding/json"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

type stepStartMessage struct {
	desc          string
	intermediates int
}
type stepDoneMessage struct{}
type tickMessage struct{}
type quitMessage struct{}
type finishMessage struct{}
type setFinalMessage struct {
	message string
}

type logFollower struct {
	stepStartEvents chan<- stepStartMessage
	stepDoneEvents  chan<- stepDoneMessage
	tickEvents      chan<- tickMessage
	quitEvents      chan<- quitMessage
	finalEvents     chan<- setFinalMessage
	finished        <-chan finishMessage
}

func (l *logFollower) StepStart(desc string, intermediates int) {
	l.stepStartEvents <- stepStartMessage{desc, intermediates}
}

func (l *logFollower) StepDone() {
	l.stepDoneEvents <- stepDoneMessage{}
}

func (l *logFollower) Tick() {
	l.tickEvents <- tickMessage{}
}

func (l *logFollower) Quit() {
	l.quitEvents <- quitMessage{}
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

	fmt.Printf("\r%s", status)
	for i := 0; i < 60-len(status)-tlen; i++ {
		fmt.Printf(".")
	}
	fmt.Printf("%s", tail)
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

var issuerKeyproofCmd = &cobra.Command{
	Use:   "keyproof [path]",
	Short: "Generate proof of correct generation for an IRMA issuer keypair",
	Long:  `Generate proof of correct generation for an IRMA issuer keypair

The keyproof command generates a proof that an issuer key was generated correctly. By default, it generates a proof for the newest private key in the PrivateKeys folder, and then stores the proof in the Proofs folder.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		counter, _ := flags.GetUint("index")
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
				return err
			}
		}
		if err = fs.AssertPathExists(path); err != nil {
			return errors.WrapPrefix(err, "Nonexisting path specified", 0)
		}

		// Determine counter if needed
		if !flags.Changed("index") {
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

		// Prepare storage for proof if needed
		if prooffile == "" {
			proofpath := filepath.Join(path, "Proofs")
			if err = fs.EnsureDirectoryExists(proofpath); err != nil {
				return errors.WrapPrefix(err, "Failed to create"+proofpath, 0)
			}
			prooffile = filepath.Join(proofpath, strconv.Itoa(int(counter))+".json.gz")
		}

		// Try to read public key
		pk, err := gabi.NewPublicKeyFromFile(pubkeyfile)
		if err != nil {
			return errors.WrapPrefix(err, "Could not read public key", 0)
		}

		// Try to read private key
		sk, err := gabi.NewPrivateKeyFromFile(privkeyfile)
		if err != nil {
			return errors.WrapPrefix(err, "Could not read private key", 0)
		}

		// Validate that they match
		if pk.N.Cmp(new(big.Int).Mul(sk.P, sk.Q)) != 0 {
			return errors.New("Private and public key do not match")
		}
		
		// Validate that the key is amenable to proving
		ConstEight := big.NewInt(8)
		ConstOne := big.NewInt(1)
		PMod := new(big.Int).Mod(sk.P, ConstEight)
		QMod := new(big.Int).Mod(sk.Q, ConstEight)
		PPrimeMod := new(big.Int).Mod(sk.PPrime, ConstEight)
		QPrimeMod := new(big.Int).Mod(sk.QPrime, ConstEight)
		if PMod.Cmp(ConstOne) == 0 || QMod.Cmp(ConstOne) == 0 ||
			PPrimeMod.Cmp(ConstOne) == 0 || QPrimeMod.Cmp(ConstOne) == 0 ||
			PMod.Cmp(QMod) == 0 || PPrimeMod.Cmp(QPrimeMod) == 0 {
			return errors.New("Private key not amenable to proving")
		}
		
		// Open proof file for writing
		proofOut, err := os.Create(prooffile)
		if err != nil {
			return errors.WrapPrefix(err, "Error opening proof file for writing", 0)
		}
		defer proofOut.Close()
		
		// Wrap it for gzip compression
		proofWriter := gzip.NewWriter(proofOut)
		defer proofWriter.Close()
		
		// Start log follower
		follower := startLogFollower()
		defer func() {
			follower.quitEvents <- quitMessage{}
			<-follower.finished
		}()
		
		// Build the proof
		s := keyproof.NewValidKeyProofStructure(pk.N, pk.Z, pk.S, pk.R)
		proof := s.BuildProof(sk.PPrime, sk.QPrime)

		// And write it to file
		follower.StepStart("Writing proof", 0)
		proofEncoder := json.NewEncoder(proofWriter)
		err = proofEncoder.Encode(proof)
		follower.StepDone()
		if err != nil {
			return errors.WrapPrefix(err, "Could not write proof", 0)
		}
		
		return nil
	},
}

var issuerKeyvalidCmd = &cobra.Command{
	Use:   "keyvalid [path]",
	Short: "Verify validity proof for an IRMA issuer key",
	Long:  `Verify the proof that an IRMA issuer key is valid.

The keyvalid command verifies proofs of validity for IRMA issuer keys. By default, it verifies the newest proof in the Proofs folder, matching it to the corresponding key in PublicKeys.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		counter, _ := flags.GetUint("index")
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
				return err
			}
		}
		if err = fs.AssertPathExists(path); err != nil {
			return errors.WrapPrefix(err, "Nonexisting path specified", 0)
		}

		// Determine counter if needed
		if !flags.Changed("index") {
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
			return errors.WrapPrefix(err, "Error reading public key", 0)
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
			return errors.WrapPrefix(err, "Error opening proof", 0)
		}
		defer proofFile.Close()
		proofGzip, err := gzip.NewReader(proofFile)
		if err != nil {
			follower.StepDone()
			return errors.WrapPrefix(err, "Error reading proof data", 0)
		}
		defer proofGzip.Close()
		proofDecoder := json.NewDecoder(proofGzip)
		var proof keyproof.ValidKeyProof
		err = proofDecoder.Decode(&proof)
		if err != nil {
			follower.StepDone()
			return errors.WrapPrefix(err, "Error reading proof data", 0)
		}
		follower.StepDone()
		
		// Construct proof structure
		s := keyproof.NewValidKeyProofStructure(pk.N, pk.Z, pk.S, pk.R)
		
		// And use it to validate the proof
		if !s.VerifyProof(proof) {
			return errors.New("Proof is invalid!")
		} else {
			follower.finalEvents <- setFinalMessage{"Proof is valid"}
		}
		
		return nil
	},
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

func lastProofIndex(path string) (counter int) {
	matches, _ := filepath.Glob(filepath.Join(path, "Proofs", "*.xml"))
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

func init() {
	issuerCmd.AddCommand(issuerKeyproofCmd)
	
	issuerKeyproofCmd.Flags().StringP("privatekey", "s", "", `File to get private key from (default "PrivateKeys/$index.xml")`)
	issuerKeyproofCmd.Flags().StringP("publickey", "p", "", `File to get public key from (default "PublicKeys/$index.xml")`)
	issuerKeyproofCmd.Flags().StringP("proof", "o", "", `File to write proof to (default "Proofs/$index.json.gz")`)
	issuerKeyproofCmd.Flags().UintP("index", "i", 0, "Key index of key to prove (default to latest)")
	
	issuerCmd.AddCommand(issuerKeyvalidCmd)
	
	issuerKeyvalidCmd.Flags().StringP("publickey", "p", "", `File of public key to verify (default "PublicKeys/$index.xml")`)
	issuerKeyvalidCmd.Flags().StringP("proof", "o", "", `File of proof to verify (default "Proofs/$index.json.gz")`)
	issuerKeyvalidCmd.Flags().UintP("index", "i", 0, "Key index of key to prove (default to latest with proof)")
}
