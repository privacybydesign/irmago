package mdocpresent

import (
	"reflect"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// annexDRequest rebuilds the request ISO/IEC 18013-5 D.4.1.1 publishes: one
// mDL DocRequest for six data elements, five with IntentToRetain true and
// "portrait" false.
//
// Constructed rather than decoded from the published bytes, which are pinned
// byte-for-byte by TestDecodeDeviceRequest_ISOAnnexDVector in the mdoc package.
// Repeating 719 bytes of hex here would test that decoder a second time and this
// translation no better.
func annexDRequest(t *testing.T) mdoc.DeviceRequest {
	t.Helper()
	docRequest, err := mdoc.NewDocRequest(mdoc.ItemsRequest{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]mdoc.DataElements{
			"org.iso.18013.5.1": {
				"family_name":        true,
				"document_number":    true,
				"driving_privileges": true,
				"issue_date":         true,
				"expiry_date":        true,
				"portrait":           false,
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	return mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{docRequest},
	}
}

// TestDcqlQueryFromDeviceRequest checks the whole mapping of one DocRequest:
// docType to Meta, each data element to a claim path, and each IntentToRetain to
// the claim that carries it.
func TestDcqlQueryFromDeviceRequest(t *testing.T) {
	query, err := DcqlQueryFromDeviceRequest(annexDRequest(t))
	if err != nil {
		t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
	}

	if len(query.Credentials) != 1 {
		t.Fatalf("got %d credential queries, want 1", len(query.Credentials))
	}
	credential := query.Credentials[0]

	if credential.Id != "doc0" {
		t.Errorf("id = %q, want %q", credential.Id, "doc0")
	}
	if credential.Format != string(clientmodels.Format_MsoMdoc) {
		t.Errorf("format = %q, want %q", credential.Format, clientmodels.Format_MsoMdoc)
	}
	if credential.Meta == nil || credential.Meta.DocTypeValue != "org.iso.18013.5.1.mDL" {
		t.Errorf("meta = %+v, want doctype_value org.iso.18013.5.1.mDL", credential.Meta)
	}
	if credential.Multiple {
		t.Error("multiple is set; a DocRequest asks for one document")
	}
	// 9.1.3 authenticates every DeviceResponse with deviceAuth, so there is no
	// unbound proximity presentation. DCQL reads an absent field as true.
	if !credential.NeedsHolderBinding() {
		t.Error("holder binding is not required; proximity always signs deviceAuth")
	}

	// Sorted: namespace, then data element identifier. Deterministic order is what
	// keeps the consent screen from reshuffling between presentations.
	want := []dcql.Claim{
		{Path: []any{"org.iso.18013.5.1", "document_number"}, IntentToRetain: true},
		{Path: []any{"org.iso.18013.5.1", "driving_privileges"}, IntentToRetain: true},
		{Path: []any{"org.iso.18013.5.1", "expiry_date"}, IntentToRetain: true},
		{Path: []any{"org.iso.18013.5.1", "family_name"}, IntentToRetain: true},
		{Path: []any{"org.iso.18013.5.1", "issue_date"}, IntentToRetain: true},
		{Path: []any{"org.iso.18013.5.1", "portrait"}, IntentToRetain: false},
	}
	if !reflect.DeepEqual(credential.Claims, want) {
		t.Fatalf("claims\n got: %+v\nwant: %+v", credential.Claims, want)
	}
}

// TestClaimOrderIsStable: Go randomises map iteration, and these claims reach a
// consent screen. Repeating the translation must give the same order every time.
func TestClaimOrderIsStable(t *testing.T) {
	request := annexDRequest(t)

	first, err := DcqlQueryFromDeviceRequest(request)
	if err != nil {
		t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
	}
	for range 20 {
		again, err := DcqlQueryFromDeviceRequest(request)
		if err != nil {
			t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
		}
		if !reflect.DeepEqual(first.Credentials[0].Claims, again.Credentials[0].Claims) {
			t.Fatalf("claim order changed between translations\nfirst: %+v\nagain: %+v",
				first.Credentials[0].Claims, again.Credentials[0].Claims)
		}
	}
}

// TestIntentToRetainSurvivesTranslation is called out separately because it is the
// one field whose loss would be invisible: the disclosure is identical either way,
// and only what the user was told about it changes.
func TestIntentToRetainSurvivesTranslation(t *testing.T) {
	docRequest, err := mdoc.NewDocRequest(mdoc.ItemsRequest{
		DocType: "eu.europa.ec.av.1",
		NameSpaces: map[string]mdoc.DataElements{
			"eu.europa.ec.av.1": {"age_over_18": true, "age_over_21": false},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewDocRequest: %v", err)
	}
	query, err := DcqlQueryFromDeviceRequest(mdoc.DeviceRequest{
		Version: mdoc.DeviceRequestVersion, DocRequests: []mdoc.DocRequest{docRequest},
	})
	if err != nil {
		t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
	}

	retain := map[string]bool{}
	for _, claim := range query.Credentials[0].Claims {
		retain[claim.Path[1].(string)] = claim.IntentToRetain
	}
	if !retain["age_over_18"] {
		t.Error("age_over_18 lost its IntentToRetain")
	}
	if retain["age_over_21"] {
		t.Error("age_over_21 gained an IntentToRetain it was not given")
	}
}

// TestMultipleDocRequests: a reader asking for several documents gets several
// credential queries, each separately identified, and no credential_sets — which
// is how DCQL spells "all of these are required".
func TestMultipleDocRequests(t *testing.T) {
	build := func(docType string) mdoc.DocRequest {
		t.Helper()
		docRequest, err := mdoc.NewDocRequest(mdoc.ItemsRequest{
			DocType:    docType,
			NameSpaces: map[string]mdoc.DataElements{docType: {"age_over_18": false}},
		}, nil)
		if err != nil {
			t.Fatalf("NewDocRequest: %v", err)
		}
		return docRequest
	}

	query, err := DcqlQueryFromDeviceRequest(mdoc.DeviceRequest{
		Version: mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{
			build("eu.europa.ec.av.1"), build("org.iso.18013.5.1.mDL"),
		},
	})
	if err != nil {
		t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
	}

	if len(query.Credentials) != 2 {
		t.Fatalf("got %d credential queries, want 2", len(query.Credentials))
	}
	if len(query.CredentialSets) != 0 {
		t.Error("credential_sets emitted; without them DCQL already requires every query to be answered")
	}
	ids := []string{query.Credentials[0].Id, query.Credentials[1].Id}
	if !reflect.DeepEqual(ids, []string{"doc0", "doc1"}) {
		t.Errorf("ids = %v, want [doc0 doc1]", ids)
	}
	if query.Credentials[0].Meta.DocTypeValue != "eu.europa.ec.av.1" ||
		query.Credentials[1].Meta.DocTypeValue != "org.iso.18013.5.1.mDL" {
		t.Error("docTypes did not stay with their own query")
	}
}

// TestQueryIdIsNotTheDocType: DCQL requires ids "consisting of alphanumeric,
// underscore or hyphen characters" and every real docType is dotted, so the id has
// to be something else.
func TestQueryIdIsNotTheDocType(t *testing.T) {
	query, err := DcqlQueryFromDeviceRequest(annexDRequest(t))
	if err != nil {
		t.Fatalf("DcqlQueryFromDeviceRequest: %v", err)
	}
	for _, credential := range query.Credentials {
		for _, r := range credential.Id {
			isAllowed := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_' || r == '-'
			if !isAllowed {
				t.Fatalf("query id %q contains %q, which DCQL does not allow in an id", credential.Id, r)
			}
		}
	}
}

// TestTranslationRejectsInvalidRequests: a request that 8.3.2.1.2.1 does not allow
// must not become a query the consent screen is built from.
func TestTranslationRejectsInvalidRequests(t *testing.T) {
	if _, err := DcqlQueryFromDeviceRequest(mdoc.DeviceRequest{}); err == nil {
		t.Error("expected an error for a zero-valued DeviceRequest")
	}
	if _, err := DcqlQueryFromDeviceRequest(mdoc.DeviceRequest{
		Version: mdoc.DeviceRequestVersion,
	}); err == nil {
		t.Error("expected an error for a request with no docRequests")
	}
}
