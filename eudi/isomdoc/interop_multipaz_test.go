package isomdoc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/stretchr/testify/require"
)

// ============================================================
// INTEROP — a request a third-party verifier actually issued
// ============================================================
//
// irmago #724 Phase 0 step 6 stands up multipaz-verifier-server and confirms it
// issues an org-iso-mdoc request; Phase 2's gate is a presentation that
// round-trips against it. This is the request half, captured so it can be
// asserted on without the server running.
//
// testdata/multipaz_verifier_dcbegin.json is the verbatim body of:
//
//	POST /verifier/dcBegin  {"format":"mdoc","docType":"eu.europa.ec.av.1",
//	    "requestId":"age_over_18","protocol":"w3c_dc_mdoc_api", ...}
//
// against multipaz-verifier-server on 127.0.0.1:8006. Everything about it was
// produced by code that is not ours, which is the point: every other test in
// this package builds its request with the same helpers it then asserts against,
// and would pass just as happily if our idea of the wire were wrong.
//
// The server is a Ktor app in the multipaz checkout:
//
//	./gradlew :multipaz-verifier-server:run      # listens on 127.0.0.1:8006

const multipazVerifierRequest = "testdata/multipaz_verifier_dcbegin.json"

// dcBeginResponse is the subset of multipaz-verifier-server's reply this needs.
type dcBeginResponse struct {
	SessionID         string `json:"sessionId"`
	DcRequestProtocol string `json:"dcRequestProtocol"`
	DcRequestString   string `json:"dcRequestString"`
}

func multipazVerifierBegin(t *testing.T) dcBeginResponse {
	t.Helper()

	raw, err := os.ReadFile(multipazVerifierRequest)
	require.NoError(t, err)

	var response dcBeginResponse
	require.NoError(t, json.Unmarshal(raw, &response))
	return response
}

// TestMultipazVerifierIssuesOrgIsoMdoc pins the protocol identifier a real
// verifier selects for this exchange. It is the value client.NewSession branches
// on, and the one this package's constant is duplicated from.
func TestMultipazVerifierIssuesOrgIsoMdoc(t *testing.T) {
	require.Equal(t, DcApiProtocolIsoMdoc, multipazVerifierBegin(t).DcRequestProtocol)
}

// TestMultipazVerifierRequestParses is the headline: their bytes, our parser.
func TestMultipazVerifierRequestParses(t *testing.T) {
	begin := multipazVerifierBegin(t)

	request, err := RequestFromDcApi([]byte(begin.DcRequestString), testOrigin)
	require.NoError(t, err, "a request a conformant verifier issued must parse")

	require.NotEmpty(t, request.DeviceRequest)
	require.NotEmpty(t, request.EncryptionInfo)

	deviceRequest, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err)
	require.NoError(t, deviceRequest.Validate())

	require.Len(t, deviceRequest.DocRequests, 1)
	items, err := deviceRequest.DocRequests[0].Items()
	require.NoError(t, err)
	require.Equal(t, "eu.europa.ec.av.1", items.DocType)
	require.Contains(t, items.NameSpaces["eu.europa.ec.av.1"], "age_over_18")
}

// TestMultipazVerifierSendsVersion11 is the reason this fixture is worth keeping.
//
// The request carries version "1.1", not the "1.0" ISO/IEC 18013-5:2021
// 8.3.2.1.2.1 fixes — because it also carries `deviceRequestInfo`, a
// second-edition member. DeviceRequest.Validate therefore checks only the MAJOR
// version, per 8.1: "An mdoc, mdoc reader or issuing authority infrastructure
// shall not give an error and continue a transaction if it receives a data
// structure having a known major version number but with an unknown minor
// version number."
//
// That was an equality check against "1.0" until 11 Sept 2026, when it refused a
// perfectly good request from this same verifier. Asserting the version here
// means a future tightening breaks a test rather than an afternoon.
func TestMultipazVerifierSendsVersion11(t *testing.T) {
	begin := multipazVerifierBegin(t)
	request, err := RequestFromDcApi([]byte(begin.DcRequestString), testOrigin)
	require.NoError(t, err)

	deviceRequest, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err)

	require.Equal(t, "1.1", deviceRequest.Version,
		"a second-edition member in the request bumps the minor version")
	require.NotEqual(t, mdoc.DeviceRequestVersion, deviceRequest.Version,
		"and it is deliberately NOT the version this package emits")
	require.NoError(t, deviceRequest.Validate(),
		"8.1 requires an unknown MINOR version to be accepted, not refused")
}

// TestMultipazVerifierUnknownMembersAreIgnored: the request carries
// `deviceRequestInfo`, which this package has no rule for. ISO/IEC TS 18013-7
// 6.4.1 is explicit that it must be tolerated — "an mDL or mDL reader shall not
// give an error solely on the basis that it does not know the data structure.
// This requirement also applies when the CDDL definition of the data structure
// does not allow the presence of additional key-value pairs in the map" — so the
// decoder must not be tightened with ExtraDecErrorUnknownField.
func TestMultipazVerifierUnknownMembersAreIgnored(t *testing.T) {
	begin := multipazVerifierBegin(t)
	request, err := RequestFromDcApi([]byte(begin.DcRequestString), testOrigin)
	require.NoError(t, err)

	var loose map[string]any
	require.NoError(t, mdoc.Unmarshal(request.DeviceRequest, &loose))
	require.Contains(t, loose, "deviceRequestInfo",
		"fixture must still carry the member this test is about")

	deviceRequest, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err, "an unknown member must not fail the decode")
	require.Len(t, deviceRequest.DocRequests, 1)
}
