package mdoc

import (
	"reflect"
	"sort"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// issuedMDoc mints a document carrying the three age attributes and attaches a
// deviceSigned, which 8.3.2.1.2.2 makes mandatory in a returned Document. A test
// can then ask it for something it does not have.
func issuedMDoc(t *testing.T) *MDoc {
	t.Helper()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	credential, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1", map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	transcript, err := NewQRSessionTranscript(testTag24("de"), testTag24("erk"))
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}
	deviceAuth, err := holder.SignDeviceAuth("eu.europa.ec.av.1", transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}
	presented, err := AttachDeviceSigned(credential, deviceAuth)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	return presented
}

// TestResponseStatusCodesAreNotSessionStatusCodes guards the one confusion these
// constants exist to prevent: Table 8 and Table 20 both define 10 and 11, with
// different meanings at different layers.
func TestResponseStatusCodesAreNotSessionStatusCodes(t *testing.T) {
	if ResponseStatusOK != 0 || ResponseStatusGeneralError != 10 ||
		ResponseStatusCBORDecodingError != 11 || ResponseStatusCBORValidationError != 12 {
		t.Fatalf("Table 8 codes are wrong: %d/%d/%d/%d",
			ResponseStatusOK, ResponseStatusGeneralError,
			ResponseStatusCBORDecodingError, ResponseStatusCBORValidationError)
	}
	// Same numbers, different tables. Table 20's 10 is a session encryption
	// failure; Table 8's 10 is the mdoc declining to answer. The constants must
	// stay separately named so a caller cannot reach for the wrong layer's.
	if uint64(StatusErrorSessionEncryption) != ResponseStatusGeneralError {
		t.Fatal("test premise changed: Table 8 and Table 20 no longer collide on 10")
	}
	if ResponseStatusCBORValidationError == uint64(StatusSessionTermination) {
		t.Fatal("Table 8 CBOR validation must not be Table 20 session termination")
	}
}

// TestErrorResponseCarriesNoDocuments pins 8.3.2.1.2.3: "If the mdoc returns a
// status code different from 0, it shall not return any documents."
func TestErrorResponseCarriesNoDocuments(t *testing.T) {
	response, err := NewErrorDeviceResponse(ResponseStatusGeneralError)
	if err != nil {
		t.Fatalf("NewErrorDeviceResponse: %v", err)
	}
	if len(response.Documents) != 0 {
		t.Fatal("an error response carries documents")
	}
	encoded, err := response.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// The optional members must be absent, not empty: the CDDL requires at least
	// one entry when present.
	var generic map[string]any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("decode generically: %v", err)
	}
	if _, present := generic["documents"]; present {
		t.Error("an error response encodes a documents member")
	}
	if _, present := generic["documentErrors"]; present {
		t.Error("documentErrors present when none were set")
	}
	if generic["status"] != uint64(ResponseStatusGeneralError) {
		t.Errorf("status = %v, want %d", generic["status"], ResponseStatusGeneralError)
	}

	// And the rule is enforced on the way out, not merely by the constructor.
	invalid := DeviceResponse{
		Version:   DeviceResponseVersion,
		Documents: []MDoc{*issuedMDoc(t)},
		Status:    ResponseStatusGeneralError,
	}
	if err := invalid.Validate(); err == nil {
		t.Error("a response with a non-zero status and documents was accepted")
	}

	if _, err := NewErrorDeviceResponse(ResponseStatusOK); err == nil {
		t.Error("NewErrorDeviceResponse accepted status 0")
	}
}

// TestSuccessfulResponseShape checks the ordinary case still encodes as it did:
// version, documents, status, and no error members.
func TestSuccessfulResponseShape(t *testing.T) {
	response := NewDeviceResponse(*issuedMDoc(t))
	if response.Version != DeviceResponseVersion || response.Status != ResponseStatusOK {
		t.Fatalf("version %q status %d", response.Version, response.Status)
	}
	encoded, err := response.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var generic map[string]any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("decode generically: %v", err)
	}
	if _, present := generic["documentErrors"]; present {
		t.Error("documentErrors present on a clean response")
	}
	if len(generic) != 3 {
		t.Errorf("response has %d members, want 3 (version, documents, status): %v", len(generic), generic)
	}
}

// TestErrorsForRequest is the gap-closer: 8.3.2.1.2.1 says the mdoc ignores
// unknown data elements, and this is how the response says which ones.
func TestErrorsForRequest(t *testing.T) {
	credential := issuedMDoc(t)

	t.Run("request fully satisfied yields no errors", func(t *testing.T) {
		errors, err := credential.ErrorsForRequest(ItemsRequest{
			DocType: "eu.europa.ec.av.1",
			NameSpaces: map[string]DataElements{
				"eu.europa.ec.av.1": {"age_over_18": false, "age_over_16": true},
			},
		})
		if err != nil {
			t.Fatalf("ErrorsForRequest: %v", err)
		}
		// nil, not an empty map: the member must be absent from the document.
		if errors != nil {
			t.Fatalf("got %v, want nil for a fully satisfied request", errors)
		}
	})

	t.Run("unknown element is reported, not fatal", func(t *testing.T) {
		errors, err := credential.ErrorsForRequest(ItemsRequest{
			DocType: "eu.europa.ec.av.1",
			NameSpaces: map[string]DataElements{
				"eu.europa.ec.av.1": {"age_over_18": false, "portrait": true, "family_name": true},
			},
		})
		if err != nil {
			t.Fatalf("ErrorsForRequest: %v", err)
		}
		want := Errors{"eu.europa.ec.av.1": ErrorItems{
			"portrait":    ErrorCodeDataNotReturned,
			"family_name": ErrorCodeDataNotReturned,
		}}
		if !reflect.DeepEqual(errors, want) {
			t.Fatalf("errors\n got: %v\nwant: %v", errors, want)
		}
		if err := errors.validate(); err != nil {
			t.Errorf("produced an Errors map that does not validate: %v", err)
		}
	})

	t.Run("whole unknown namespace is reported", func(t *testing.T) {
		errors, err := credential.ErrorsForRequest(ItemsRequest{
			DocType: "eu.europa.ec.av.1",
			NameSpaces: map[string]DataElements{
				"org.iso.18013.5.1": {"family_name": true},
			},
		})
		if err != nil {
			t.Fatalf("ErrorsForRequest: %v", err)
		}
		if len(errors) != 1 || errors["org.iso.18013.5.1"]["family_name"] != ErrorCodeDataNotReturned {
			t.Fatalf("got %v, want family_name reported under the unknown namespace", errors)
		}
	})
}

// TestPartialResponseIsStillStatusOK is the behaviour the gap was about: a request
// naming one element too many must produce a document plus errors, not a failed
// response.
func TestPartialResponseIsStillStatusOK(t *testing.T) {
	credential := issuedMDoc(t)
	requested := ItemsRequest{
		DocType: "eu.europa.ec.av.1",
		NameSpaces: map[string]DataElements{
			"eu.europa.ec.av.1": {"age_over_18": false, "portrait": true},
		},
	}

	errors, err := credential.ErrorsForRequest(requested)
	if err != nil {
		t.Fatalf("ErrorsForRequest: %v", err)
	}
	document := *credential
	document.Errors = errors

	response := NewDeviceResponse(document)
	if response.Status != ResponseStatusOK {
		t.Fatalf("status = %d, want 0: a partly answerable request is not a failed response", response.Status)
	}
	encoded, err := response.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := decodeDeviceResponse(t, encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(decoded.Documents))
	}
	if got := decoded.Documents[0].Errors["eu.europa.ec.av.1"]["portrait"]; got != ErrorCodeDataNotReturned {
		t.Fatalf("portrait error code = %d, want %d", got, ErrorCodeDataNotReturned)
	}
	if _, reported := decoded.Documents[0].Errors["eu.europa.ec.av.1"]["age_over_18"]; reported {
		t.Error("an element that was returned is also reported as an error")
	}
}

// decodeDeviceResponse decodes under this package's strict 8.1 rules.
func decodeDeviceResponse(t *testing.T, data []byte) (DeviceResponse, error) {
	t.Helper()
	var response DeviceResponse
	err := mdocDecMode.Unmarshal(data, &response)
	return response, err
}

// TestDocumentErrorsForUnreturnedDocuments covers the other failure kind: a whole
// document that is not being returned, which is documentErrors rather than a
// document's own errors.
func TestDocumentErrorsForUnreturnedDocuments(t *testing.T) {
	documentError, err := NewDocumentError("org.iso.18013.5.1.mDL", ErrorCodeDataNotReturned)
	if err != nil {
		t.Fatalf("NewDocumentError: %v", err)
	}
	response := NewDeviceResponse(*issuedMDoc(t)).WithDocumentErrors(documentError)

	encoded, err := response.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := decodeDeviceResponse(t, encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.DocumentErrors) != 1 {
		t.Fatalf("got %d documentErrors, want 1", len(decoded.DocumentErrors))
	}
	if decoded.DocumentErrors[0]["org.iso.18013.5.1.mDL"] != ErrorCodeDataNotReturned {
		t.Errorf("documentErrors = %v", decoded.DocumentErrors[0])
	}
	// A returned document alongside an unreturned one is still status 0.
	if decoded.Status != ResponseStatusOK {
		t.Errorf("status = %d, want 0", decoded.Status)
	}

	if _, err := NewDocumentError("", ErrorCodeDataNotReturned); err == nil {
		t.Error("NewDocumentError accepted an empty docType")
	}
}

// TestResponseValidationRejects covers the CDDL's `+` occurrences and the version.
func TestResponseValidationRejects(t *testing.T) {
	credential := issuedMDoc(t)

	t.Run("wrong version", func(t *testing.T) {
		response := NewDeviceResponse(*credential)
		response.Version = "1.1"
		if err := response.Validate(); err == nil {
			t.Fatal("expected an error for a version other than 1.0")
		}
	})

	t.Run("empty Errors map", func(t *testing.T) {
		if err := (Errors{}).validate(); err == nil {
			t.Fatal("an empty Errors map validated")
		}
		// An explicitly empty map is not "no errors". It has to be caught rather
		// than left to omitempty, which would silently drop it and encode a
		// document that claims nothing went wrong.
		document := *credential
		document.Errors = Errors{}
		if err := NewDeviceResponse(document).Validate(); err == nil {
			t.Fatal("a document with an explicitly empty Errors map was accepted")
		}
	})

	t.Run("namespace with no items", func(t *testing.T) {
		document := *credential
		document.Errors = Errors{"eu.europa.ec.av.1": ErrorItems{}}
		if err := NewDeviceResponse(document).Validate(); err == nil {
			t.Fatal("an Errors namespace with no data elements was accepted")
		}
	})

	t.Run("empty documentError", func(t *testing.T) {
		response := NewDeviceResponse(*credential).WithDocumentErrors(DocumentError{})
		if err := response.Validate(); err == nil {
			t.Fatal("an empty documentError was accepted")
		}
	})
}

// TestDisclosedElements checks the accessor ErrorsForRequest is built on.
func TestDisclosedElements(t *testing.T) {
	disclosed, err := issuedMDoc(t).DisclosedElements()
	if err != nil {
		t.Fatalf("DisclosedElements: %v", err)
	}
	got := disclosed["eu.europa.ec.av.1"]
	sort.Strings(got)
	want := []string{"age_over_16", "age_over_18", "age_over_21"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disclosed elements\n got: %v\nwant: %v", got, want)
	}
}
