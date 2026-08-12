package lote

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The normative Annex A JSON schema, vendored from ETSI's own repository.
//
// It is embedded rather than fetched so that conformance is a property of the
// build rather than of the network, and vendored rather than reimplemented
// because it *is* the compliance target: TS 119 602 Annex A designates this repo
// as the JSON binding, and every EU profile requires conformance to it.
//
// Provenance: forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities at tag
// v1.1.1, BSD-3-Clause. schema/LICENSE is ETSI's, retained as clause 1 of that
// licence requires. Update it by re-copying from a *tagged* upstream revision and
// bumping SchemaVersion — never by hand-editing, because Annex A states the PDF
// prevails over the schema, so a locally patched copy would diverge from every
// other validator while still looking authoritative.
//
//go:embed schema/1960201_json_schema.json schema/rfcs/rfc7517.json
var schemaFS embed.FS

// SchemaVersion is the upstream tag the embedded schema was copied from.
const SchemaVersion = "v1.1.1"

// schemaBaseURI identifies the embedded schema. It is the upstream URL so the
// relative `rfcs/rfc7517.json` reference inside the schema resolves the way it
// does upstream, and so an error message names something a reader can go and look
// at.
const schemaBaseURI = "https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities/1960201_json_schema.json"

// compiledSchema compiles once. Compiling is not cheap and a publisher validates
// every document it builds.
var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()

	for path, uri := range map[string]string{
		"schema/1960201_json_schema.json": schemaBaseURI,
		"schema/rfcs/rfc7517.json":        "https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities/rfcs/rfc7517.json",
	} {
		file, err := schemaFS.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open embedded %s: %w", path, err)
		}
		doc, err := jsonschema.UnmarshalJSON(file)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("parse embedded %s: %w", path, err)
		}
		if err := compiler.AddResource(uri, doc); err != nil {
			return nil, fmt.Errorf("add embedded %s: %w", path, err)
		}
	}

	return compiler.Compile(schemaBaseURI)
})

// ValidateDocument reports whether raw is a conformant Annex A LoTE document.
//
// This is the check that makes "we are standards compliant" a testable claim
// rather than an intention. It is deliberately separate from [VerifySigned]:
// conformance is a property of the document, and the wallet does *not* apply it —
// a wallet that refused a document over a schema detail it does not care about
// would be brittle for no gain. Enforcing it is the publisher's job, at build
// time, which is the last moment it is cheap.
//
// One thing it cannot catch: the schema's `ServiceDigitalIdentity` places
// `additionalProperties: false` inside its `properties` object, so it declares a
// member by that name instead of constraining unknown ones. Unknown members of a
// service's digital identity therefore pass. See
// docs/plans/lote-annex-a-publisher.md § Errata.
func ValidateDocument(raw []byte) error {
	schema, err := compiledSchema()
	if err != nil {
		return fmt.Errorf("compile the embedded Annex A schema: %w", err)
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse the document: %w", err)
	}

	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("the document does not conform to ETSI TS 119 602 Annex A (%s):\n%s",
			SchemaVersion, indentValidationError(err))
	}
	return nil
}

// ValidateList marshals a list and validates the document it produces, for
// callers holding a [List] rather than bytes.
func ValidateList(list List) error {
	raw, err := json.Marshal(Document{LoTE: list})
	if err != nil {
		return fmt.Errorf("marshal the document: %w", err)
	}
	return ValidateDocument(raw)
}

// indentValidationError renders a schema failure so the offending field is
// readable. The library's default rendering is one long line; a publisher reading
// this is trying to find out which entity is wrong.
func indentValidationError(err error) string {
	var detailed *jsonschema.ValidationError
	if !errors.As(err, &detailed) {
		return err.Error()
	}

	var out strings.Builder
	for _, line := range strings.Split(detailed.Error(), "\n") {
		out.WriteString("  ")
		out.WriteString(strings.TrimSpace(line))
		out.WriteString("\n")
	}
	return strings.TrimRight(out.String(), "\n")
}
