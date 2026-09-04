package mdoc_dcql

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// ---------------------------------------------------------------------------
// DeviceKeyBinder — the seam that lets the device key live in hardware
// ---------------------------------------------------------------------------

// nonExtractableSigner stands in for an Android StrongBox / Secure Enclave key
// handle: it signs, it names its public key, and it has no method that returns
// the private half. A presentation produced with one of these has demonstrably
// not taken a path through key material.
type nonExtractableSigner struct {
	key   *ecdsa.PrivateKey
	calls int
}

func (s *nonExtractableSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *nonExtractableSigner) Sign(rnd io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.calls++
	// DER, the form Android Keystore's SHA256withECDSA returns.
	return ecdsa.SignASN1(rnd, s.key, digest)
}

// hardwareDeviceKeyBinder is a DeviceKeyBinder whose keys are never in process as
// keys: it resolves the device key the handler asks for to a Holder built on a
// nonExtractableSigner. It records what it was asked for, since "the handler asks
// for the key the credential is bound to" is the property that decides whether a
// presentation verifies at all.
type hardwareDeviceKeyBinder struct {
	available []*ecdsa.PrivateKey
	asked     []*ecdsa.PublicKey
	signers   []*nonExtractableSigner
	err       error
}

func (b *hardwareDeviceKeyBinder) HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (stdmdoc.Holder, error) {
	b.asked = append(b.asked, deviceKey)
	if b.err != nil {
		return nil, b.err
	}
	for _, candidate := range b.available {
		if candidate.PublicKey.Equal(deviceKey) {
			signer := &nonExtractableSigner{key: candidate}
			b.signers = append(b.signers, signer)
			return stdmdoc.NewHolderFromSigner(signer)
		}
	}
	return nil, fmt.Errorf("no hardware key for the requested device key")
}

// TestPrepareDisclosureSignsWithNonExtractableDeviceKey is what the binder seam
// exists for: a device key this process cannot read still produces a presentation
// the verifier accepts, deviceAuth and all, and nothing in the handler knows the
// difference.
func TestPrepareDisclosureSignsWithNonExtractableDeviceKey(t *testing.T) {
	env := newTestEnv(t)
	binder := &hardwareDeviceKeyBinder{available: env.deviceKeys}

	prepared, err := env.withDeviceKeyBinder(binder).disclose(t)
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
	assert.True(t, results[0].Valid, "verification failed: %s", results[0].Error)
	assert.True(t, results[0].DeviceAuthValid,
		"deviceAuth signed by a non-extractable key did not verify: %s", results[0].Error)

	// The signing really went through the opaque signer, rather than any key the
	// handler found for itself.
	require.Len(t, binder.signers, 1)
	assert.Equal(t, 1, binder.signers[0].calls,
		"the device key must be used exactly once per presentation")
}

// TestPrepareDisclosureAsksForTheKeyTheCredentialIsBoundTo pins where the handler
// takes the device key identity from. Asking the credential's own MSO is what
// makes the signature verifiable: the verifier reads deviceKeyInfo out of that
// same MSO, so a handler resolving the signer from anywhere else could sign with a
// key the credential is not bound to and fail only at the verifier.
func TestPrepareDisclosureAsksForTheKeyTheCredentialIsBoundTo(t *testing.T) {
	env := newTestEnv(t)
	binder := &hardwareDeviceKeyBinder{available: env.deviceKeys}

	_, err := env.withDeviceKeyBinder(binder).disclose(t)
	require.NoError(t, err)

	require.Len(t, binder.asked, 1, "one presentation must resolve exactly one device key")
	require.Len(t, env.deviceKeys, 1)
	assert.True(t, env.deviceKeys[0].PublicKey.Equal(binder.asked[0]),
		"the handler asked for a device key other than the one the credential's MSO names")
}

// TestPrepareDisclosureFailingBinderSpendsNoInstance covers the failure a hardware
// binder makes newly possible -- the platform refusing to sign, because the user
// did not authenticate to the key -- and pins that it costs the wallet nothing.
// Signing happens before the instance is marked used, so a refusal must leave the
// batch as it was rather than burning a single-use credential on a presentation
// that never reached a verifier.
func TestPrepareDisclosureFailingBinderSpendsNoInstance(t *testing.T) {
	env := newTestEnvWithBatchSize(t, 2)
	binder := &hardwareDeviceKeyBinder{err: fmt.Errorf("user did not authenticate")}

	_, err := env.withDeviceKeyBinder(binder).disclose(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user did not authenticate",
		"the platform's own reason for refusing must survive to the caller")

	batch, err := env.store.GetBatchByHash(env.hash)
	require.NoError(t, err)
	assert.Equal(t, uint(2), batch.RemainingCount,
		"a presentation that was never signed must not spend a batch instance")
}

// TestPrepareDisclosureNamesTheInstanceWhenNoDeviceKeyIsAvailable covers the other
// binder failure: the wallet holds a credential whose device key it has no signer
// for. That credential can never be presented, so the error has to identify which
// one rather than reading as a transient signing failure.
func TestPrepareDisclosureNamesTheInstanceWhenNoDeviceKeyIsAvailable(t *testing.T) {
	env := newTestEnv(t)
	// A binder holding no keys at all: every lookup misses.
	binder := &hardwareDeviceKeyBinder{}

	_, err := env.withDeviceKeyBinder(binder).disclose(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential instance",
		"the error must name the instance whose device key is missing")
	assert.Contains(t, err.Error(), "no hardware key for the requested device key",
		"the binder's own diagnosis must not be swallowed")
}

// TestDefaultBinderIsWhatTheHandlerUsesByDefault guards the wiring the tests above
// rest on: newTestEnv builds the handler with the production binder, so any
// presentation prepared without substituting one is evidence about the real path.
func TestDefaultBinderIsWhatTheHandlerUsesByDefault(t *testing.T) {
	env := newTestEnv(t)

	prepared, err := env.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		ResponseUri:          testResponseU,
	}}, testNonce, testClientId)

	require.NoError(t, err, "the storage-backed binder must resolve the key issuance stored")
	require.Len(t, prepared.QueryResponses, 1)
}
