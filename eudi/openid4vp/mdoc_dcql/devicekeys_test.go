package mdoc_dcql

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/holdersigning"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// ---------------------------------------------------------------------------
// DeviceKeys — the seam that lets the device key live outside this process
// ---------------------------------------------------------------------------

// hardwareDeviceKeys is a DeviceKeys whose keys are never in the handler's
// reach: it resolves the device key the handler asks for to an external
// reference, which only hardwareSigner can sign with. It records what it was
// asked for, since "the handler asks for the key the credential is bound to"
// is the property that decides whether a presentation verifies at all.
type hardwareDeviceKeys struct {
	available []*ecdsa.PrivateKey
	asked     []*ecdsa.PublicKey
}

func (k *hardwareDeviceKeys) ResolveDeviceKey(deviceKey *ecdsa.PublicKey) (holdersigning.Key, error) {
	k.asked = append(k.asked, deviceKey)
	for i, candidate := range k.available {
		if candidate.PublicKey.Equal(deviceKey) {
			return holdersigning.External(fmt.Sprintf("hardware-key-%d", i)), nil
		}
	}
	return holdersigning.Key{}, fmt.Errorf("no hardware key for the requested device key")
}

// hardwareSigner stands in for whatever holds hardwareDeviceKeys' keys: a
// wallet provider's HSM, StrongBox, the Secure Enclave. It signs the exact
// input it is handed, and counts the calls.
type hardwareSigner struct {
	keys  *hardwareDeviceKeys
	calls int
	err   error
}

func (s *hardwareSigner) Sign(_ context.Context, reqs []holdersigning.Request) ([][]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	sigs := make([][]byte, len(reqs))
	for i, req := range reqs {
		var index int
		if _, err := fmt.Sscanf(req.Key.ExternalRef(), "hardware-key-%d", &index); err != nil {
			return nil, fmt.Errorf("not a hardware key: %q", req.Key.ExternalRef())
		}
		sig, err := holdersigning.SignSoftware(holdersigning.Software(s.keys.available[index]), req.Input)
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// TestPrepareDisclosureSignsWithExternalDeviceKey is what the seam exists for: a
// device key this handler cannot read still produces a presentation the
// verifier accepts, deviceAuth and all, and nothing in the handler knows the
// difference.
func TestPrepareDisclosureSignsWithExternalDeviceKey(t *testing.T) {
	env := newTestEnv(t)
	keys := &hardwareDeviceKeys{available: env.deviceKeys}
	signer := &hardwareSigner{keys: keys}

	prepared, err := env.withDeviceKeys(keys).discloseWith(t, signer)
	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	require.Len(t, prepared.QueryResponses[0].Credentials, 1)

	encoded, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)
	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))

	transcript, err := newOpenID4VPSessionTranscript(testClientId, testNonce, testResponseU, nil)
	require.NoError(t, err)

	results, err := env.verifier.VerifyDeviceResponse(response, testNamespace, testDocType, transcript)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Valid, "verification failed: %s", results[0].Error)
	require.True(t, results[0].DeviceAuthValid,
		"deviceAuth signed by an external key did not verify: %s", results[0].Error)

	require.Equal(t, 1, signer.calls, "the presentation is signed in one call")
}

// TestPrepareDisclosureAsksForTheKeyTheCredentialIsBoundTo pins where the handler
// takes the device key identity from. Asking the credential's own MSO is what
// makes the signature verifiable: the verifier reads deviceKeyInfo out of that
// same MSO, so a handler resolving the key from anywhere else could sign with a
// key the credential is not bound to and fail only at the verifier.
func TestPrepareDisclosureAsksForTheKeyTheCredentialIsBoundTo(t *testing.T) {
	env := newTestEnv(t)
	keys := &hardwareDeviceKeys{available: env.deviceKeys}

	_, err := env.withDeviceKeys(keys).discloseWith(t, &hardwareSigner{keys: keys})
	require.NoError(t, err)

	require.Len(t, keys.asked, 1, "one presentation must resolve exactly one device key")
	require.Len(t, env.deviceKeys, 1)
	require.True(t, env.deviceKeys[0].PublicKey.Equal(keys.asked[0]),
		"the handler asked for a device key other than the one the credential's MSO names")
}

// TestPrepareDisclosureFailingSignerSpendsNoInstance covers the failure an
// external key makes newly possible -- the key holder refusing to sign,
// because the user did not enter their PIN -- and pins that it costs the
// wallet nothing. Instances are marked used only once the disclosure is
// signed, so a refusal must leave the batch as it was rather than burning a
// single-use credential on a presentation that never reached a verifier.
func TestPrepareDisclosureFailingSignerSpendsNoInstance(t *testing.T) {
	env := newTestEnvWithBatchSize(t, 2)
	keys := &hardwareDeviceKeys{available: env.deviceKeys}
	signer := &hardwareSigner{keys: keys, err: fmt.Errorf("user did not authenticate")}

	_, err := env.withDeviceKeys(keys).discloseWith(t, signer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "user did not authenticate",
		"the key holder's own reason for refusing must survive to the caller")

	batch, err := env.store.GetBatchByHash(env.hash)
	require.NoError(t, err)
	require.Equal(t, uint(2), batch.RemainingCount,
		"a presentation that was never signed must not spend a batch instance")
}

// TestPrepareDisclosureNamesTheInstanceWhenNoDeviceKeyIsAvailable covers the
// wallet holding a credential whose device key it cannot resolve. That
// credential can never be presented, so the error has to identify which one
// rather than reading as a transient signing failure.
func TestPrepareDisclosureNamesTheInstanceWhenNoDeviceKeyIsAvailable(t *testing.T) {
	env := newTestEnv(t)
	// A resolver holding no keys at all: every lookup misses.
	keys := &hardwareDeviceKeys{}

	_, err := env.withDeviceKeys(keys).discloseWith(t, &hardwareSigner{keys: keys})
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential instance",
		"the error must name the instance whose device key is missing")
	require.Contains(t, err.Error(), "no hardware key for the requested device key",
		"the resolver's own diagnosis must not be swallowed")
}

// TestPrepareDisclosureDistinctInstancesForOneBatch pins that selecting the
// same batch twice in one disclosure presents two different instances, even
// though neither is marked used until both are signed.
func TestPrepareDisclosureDistinctInstancesForOneBatch(t *testing.T) {
	env := newTestEnvWithBatchSize(t, 2)
	keys := &hardwareDeviceKeys{available: env.deviceKeys}

	sel := dcql.DisclosureSelection{
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		ResponseUri:          testResponseU,
	}
	first, second := sel, sel
	first.QueryId, second.QueryId = "a", "b"
	_, err := prepareSignedWith(env.withDeviceKeys(keys).handler, &hardwareSigner{keys: keys},
		[]dcql.DisclosureSelection{first, second}, testNonce, testClientId)
	require.NoError(t, err)

	require.Len(t, keys.asked, 2)
	require.False(t, keys.asked[0].Equal(keys.asked[1]), "both selections presented the same instance")
	batch, err := env.store.GetBatchByHash(env.hash)
	require.NoError(t, err)
	require.Zero(t, batch.RemainingCount)
}

// TestDefaultResolverIsWhatTheHandlerUsesByDefault guards the wiring the tests
// above rest on: newTestEnv builds the handler with the production resolver,
// so any presentation prepared without substituting one is evidence about the
// real path.
func TestDefaultResolverIsWhatTheHandlerUsesByDefault(t *testing.T) {
	env := newTestEnv(t)

	prepared, err := prepareSigned(env.handler, []dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		ResponseUri:          testResponseU,
	}}, testNonce, testClientId)

	require.NoError(t, err, "the storage-backed resolver must resolve the key issuance stored")
	require.Len(t, prepared.QueryResponses, 1)
}
