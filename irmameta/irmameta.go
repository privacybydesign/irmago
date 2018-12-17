// irmameta parses and prints info about the specified metadata attribute.
package main

import (
	"encoding/base64"
	"fmt"

	"os"
	"time"

	"encoding/json"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: irmago path_to_irma_configuration metadata_attribute_in_decimal")
	}

	metaint := new(big.Int)
	_, ok := metaint.SetString(os.Args[2], 10)
	if !ok {
		bts, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			fmt.Println("Could not parse argument as decimal or base64 integer: ", err.Error())
			os.Exit(1)
		}
		metaint.SetBytes(bts)
	}

	confpath := os.Args[1]
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
	fmt.Println("IsValid         :", meta.IsValid())
	fmt.Println("Version         :", meta.Version())
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
