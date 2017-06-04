package irmago

import (
	"fmt"
	"testing"
)

func TestParseStore(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", MetaStore.issuers["irma-demo.MijnOverheid"].CurrentPublicKey())
}
