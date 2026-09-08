package mdoc

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// isoAnnexDDeviceRequest is the mdoc request published in ISO/IEC 18013-5:2021
// D.4.1.1. Its diagnostic notation in the standard is:
//
//	{
//	   "version": "1.0",
//	   "docRequests": [{
//	       "itemsRequest": 24(<< {
//	           "docType": "org.iso.18013.5.1.mDL",
//	           "nameSpaces": { "org.iso.18013.5.1": {
//	               "family_name": true, "document_number": true,
//	               "driving_privileges": true, "issue_date": true,
//	               "expiry_date": true, "portrait": false
//	           }}
//	       } >>),
//	       "readerAuth": [<< {1: -7} >>, {33: h'3082…'}, null, h'1F34…']
//	   }]
//	}
//
// Two things make it a good vector beyond the structure: "portrait" carries
// IntentToRetain false while the other five carry true, so a translation that
// dropped or defaulted the flag would still pass a shape test but fail this one;
// and readerAuth is present, which exercises the optional member and the
// requirement to keep it byte-exact.
const isoAnnexDDeviceRequest = "" +
	"a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893a267646f" +
	"6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e" +
	"31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d626572f57264726976696e67" +
	"5f70726976696c65676573f56a69737375655f64617465f56b6578706972795f64617465f568706f727472616974f46a" +
	"726561646572417574688443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba" +
	"175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d" +
	"3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c0672656164657230" +
	"59301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628d" +
	"ff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185" +
	"301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f3" +
	"0b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e" +
	"0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403" +
	"020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d7" +
	"39dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c58" +
	"9424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf"

// TestDecodeDeviceRequest_ISOAnnexDVector checks the decoded request against the
// diagnostic notation ISO prints beside the bytes, element by element including
// each IntentToRetain flag.
func TestDecodeDeviceRequest_ISOAnnexDVector(t *testing.T) {
	request, err := DecodeDeviceRequest(mustHex(t, isoAnnexDDeviceRequest))
	if err != nil {
		t.Fatalf("DecodeDeviceRequest: %v", err)
	}

	if request.Version != DeviceRequestVersion {
		t.Errorf("version = %q, want %q", request.Version, DeviceRequestVersion)
	}
	if len(request.DocRequests) != 1 {
		t.Fatalf("got %d docRequests, want 1", len(request.DocRequests))
	}
	if len(request.DocRequests[0].ReaderAuth) == 0 {
		t.Error("readerAuth is absent; D.4.1.1 carries one")
	}

	items, err := request.DocRequests[0].Items()
	if err != nil {
		t.Fatalf("Items: %v", err)
	}
	if items.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType = %q", items.DocType)
	}
	if len(items.NameSpaces) != 1 {
		t.Fatalf("got %d namespaces, want 1", len(items.NameSpaces))
	}

	elements, ok := items.NameSpaces["org.iso.18013.5.1"]
	if !ok {
		t.Fatalf("namespace org.iso.18013.5.1 missing; got %v", items.NameSpaces)
	}
	want := map[string]bool{
		"family_name":        true,
		"document_number":    true,
		"driving_privileges": true,
		"issue_date":         true,
		"expiry_date":        true,
		"portrait":           false, // the one element the verifier does not intend to retain
	}
	if len(elements) != len(want) {
		t.Fatalf("got %d data elements, want %d: %v", len(elements), len(want), elements)
	}
	for identifier, intentToRetain := range want {
		got, present := elements[identifier]
		if !present {
			t.Errorf("data element %q missing", identifier)
			continue
		}
		if got != intentToRetain {
			t.Errorf("%q IntentToRetain = %v, want %v", identifier, got, intentToRetain)
		}
	}
}

// TestDeviceRequest_ReEncodesToISOAnnexDVector requires a decoded request to go
// back out as the bytes it came in as.
//
// This matters more here than elsewhere: 9.1.4 signs ItemsRequestBytes, so any
// difference between what arrived and what this package holds would break reader
// authentication for a request that was perfectly valid. Keeping both
// itemsRequest and readerAuth as raw CBOR is what makes it hold.
func TestDeviceRequest_ReEncodesToISOAnnexDVector(t *testing.T) {
	golden := mustHex(t, isoAnnexDDeviceRequest)

	request, err := DecodeDeviceRequest(golden)
	if err != nil {
		t.Fatalf("DecodeDeviceRequest: %v", err)
	}
	got, err := request.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("re-encode does not match ISO D.4.1.1\n got: %x\nwant: %x", got, golden)
	}
}

// TestItemsRequestBytesArePreservedForReaderAuth pins the specific byte
// preservation 9.1.4 depends on: DocRequest.ItemsRequest must be the tag-24 item
// exactly as received, not a re-encoding of the parsed ItemsRequest.
func TestItemsRequestBytesArePreservedForReaderAuth(t *testing.T) {
	request, err := DecodeDeviceRequest(mustHex(t, isoAnnexDDeviceRequest))
	if err != nil {
		t.Fatalf("DecodeDeviceRequest: %v", err)
	}
	raw := request.DocRequests[0].ItemsRequest

	if len(raw) < 2 || raw[0] != 0xd8 || raw[1] != 0x18 {
		t.Fatalf("ItemsRequest is not a tag-24 item on the wire: %x", raw)
	}
	if !bytes.Contains(mustHex(t, isoAnnexDDeviceRequest), raw) {
		t.Fatal("ItemsRequestBytes are not a verbatim slice of the received request")
	}
}

// TestNewDocRequestRoundTrips covers the reader-side constructor, which the Go
// test reader will use to build requests.
func TestNewDocRequestRoundTrips(t *testing.T) {
	items := ItemsRequest{
		DocType: "eu.europa.ec.av.1",
		NameSpaces: map[string]DataElements{
			"eu.europa.ec.av.1": {"age_over_18": false},
		},
	}
	docRequest, err := NewDocRequest(items, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	request := DeviceRequest{Version: DeviceRequestVersion, DocRequests: []DocRequest{docRequest}}

	encoded, err := request.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeDeviceRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeDeviceRequest: %v", err)
	}
	gotItems, err := decoded.DocRequests[0].Items()
	if err != nil {
		t.Fatalf("Items: %v", err)
	}
	if gotItems.DocType != items.DocType {
		t.Errorf("docType = %q, want %q", gotItems.DocType, items.DocType)
	}
	if retain, ok := gotItems.NameSpaces["eu.europa.ec.av.1"]["age_over_18"]; !ok || retain {
		t.Errorf("age_over_18 = (%v, present=%v), want (false, true)", retain, ok)
	}
	if len(decoded.DocRequests[0].ReaderAuth) != 0 {
		t.Error("readerAuth present on a request built without one")
	}
}

// TestDeviceRequestValidation covers the version and the CDDL's three `+`
// occurrences, each of which requires at least one member. All three are
// well-formed CBOR and meaningless as a request.
func TestDeviceRequestValidation(t *testing.T) {
	validItems := ItemsRequest{
		DocType:    "eu.europa.ec.av.1",
		NameSpaces: map[string]DataElements{"eu.europa.ec.av.1": {"age_over_18": false}},
	}
	validDoc, err := NewDocRequest(validItems, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}

	t.Run("wrong version", func(t *testing.T) {
		request := DeviceRequest{Version: "1.1", DocRequests: []DocRequest{validDoc}}
		if err := request.Validate(); err == nil {
			t.Fatal("expected an error for a version other than 1.0")
		}
	})

	t.Run("no docRequests", func(t *testing.T) {
		request := DeviceRequest{Version: DeviceRequestVersion}
		if err := request.Validate(); err == nil {
			t.Fatal("expected an error for an empty docRequests array")
		}
	})

	t.Run("no nameSpaces", func(t *testing.T) {
		if _, err := NewDocRequest(ItemsRequest{DocType: "eu.europa.ec.av.1"}, nil); err == nil {
			t.Fatal("expected an error for an ItemsRequest with no nameSpaces")
		}
	})

	t.Run("namespace with no data elements", func(t *testing.T) {
		_, err := NewDocRequest(ItemsRequest{
			DocType:    "eu.europa.ec.av.1",
			NameSpaces: map[string]DataElements{"eu.europa.ec.av.1": {}},
		}, nil)
		if err == nil {
			t.Fatal("expected an error for a namespace requesting no data elements")
		}
	})

	t.Run("no docType", func(t *testing.T) {
		_, err := NewDocRequest(ItemsRequest{
			NameSpaces: map[string]DataElements{"ns": {"element": false}},
		}, nil)
		if err == nil {
			t.Fatal("expected an error for an ItemsRequest with no docType")
		}
	})

	t.Run("itemsRequest not tag-24", func(t *testing.T) {
		request := DeviceRequest{
			Version:     DeviceRequestVersion,
			DocRequests: []DocRequest{{ItemsRequest: cbor.RawMessage(mustHex(t, "63646566"))}},
		}
		if err := request.Validate(); err == nil {
			t.Fatal("expected an error for an ItemsRequest that is not a tag-24 item")
		}
	})
}

// TestRequestInfoIsCarriedNotInterpreted covers "This document does not define any
// key-value pairs for use in requestInfo. An mdoc shall ignore any key-value pairs
// that it is not able to interpret." Ignoring must not mean failing.
func TestRequestInfoIsCarriedNotInterpreted(t *testing.T) {
	items := ItemsRequest{
		DocType:    "eu.europa.ec.av.1",
		NameSpaces: map[string]DataElements{"eu.europa.ec.av.1": {"age_over_18": false}},
		RequestInfo: map[string]cbor.RawMessage{
			"somethingTheReaderInvented": cbor.RawMessage(mustHex(t, "63646566")),
		},
	}
	docRequest, err := NewDocRequest(items, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	encoded, err := DeviceRequest{
		Version: DeviceRequestVersion, DocRequests: []DocRequest{docRequest},
	}.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeDeviceRequest(encoded)
	if err != nil {
		t.Fatalf("an unrecognised requestInfo entry must be ignored, not rejected: %v", err)
	}
	gotItems, err := decoded.DocRequests[0].Items()
	if err != nil {
		t.Fatalf("Items: %v", err)
	}
	if len(gotItems.RequestInfo) != 1 {
		t.Errorf("requestInfo was dropped rather than carried: %v", gotItems.RequestInfo)
	}
}
