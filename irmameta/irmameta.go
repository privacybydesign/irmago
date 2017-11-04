package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"time"

	"encoding/json"

	"github.com/credentials/irmago"
	"github.com/mhe/gabi"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: irmago metadata_attribute_in_decimal path_to_irma_configuration")
	}

	metaint, ok := new(big.Int).SetString(os.Args[1], 10)
	if !ok {
		fmt.Println("Could not parse argument as decimal integer:")
		os.Exit(1)
	}

	confpath := os.Args[2]
	conf, err := irma.NewConfiguration(confpath, "")
	if err != nil {
		fmt.Println("Failed to parse irma_configuration:", err)
		os.Exit(1)
	}
	err = conf.ParseFolder()
	if err != nil {
		fmt.Println("Failed to parse irma_configuration:", err)
		os.Exit(1)
	}

	meta := irma.MetadataFromInt(metaint, conf)
	typ := meta.CredentialType()
	var key *gabi.PublicKey

	if typ == nil {
		fmt.Println("Unknown credential type, hash:", base64.StdEncoding.EncodeToString(meta.CredentialTypeHash()))
	} else {
		fmt.Println("Identifier      :", typ.Identifier())
		key, err = meta.PublicKey()
		if err != nil {
			fmt.Println("Failed to parse public key", err)
		}
	}
	fmt.Println("Signed          :", meta.SigningDate().String())
	fmt.Println("Expires         :", meta.Expiry().String())
	fmt.Println("IsValid()       :", meta.IsValid())
	fmt.Println("KeyCounter      :", meta.KeyCounter())
	if key != nil {
		fmt.Println("KeyExpires      :", time.Unix(key.ExpiryDate, 0))
		fmt.Println("KeyModulusBitlen:", key.N.BitLen())
	}

	fmt.Println()
	fmt.Println("CredentialType  :", prettyprint(typ))
}

func prettyprint(ob interface{}) string {
	b, err := json.MarshalIndent(ob, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(b)
}
