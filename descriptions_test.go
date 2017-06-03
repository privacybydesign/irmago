package irmago

import "testing"

func TestParseStore(t *testing.T) {
	err := MetaStore.ParseFolder("testdata/irma_configuration")
	if err != nil {
		t.Fatal(err)
	}
}
