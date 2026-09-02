package eudicli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	Logger = logrus.New()
	Logger.SetOutput(io.Discard)
}

// The committed example under testdata/walletconfig/source is both the worked
// example an operator copies and the fixture these tests compile, and it builds
// the golden payload byte for byte, so the example cannot rot into something
// `build` would refuse and the two fixtures cannot drift apart.

var goldenIssuedAt = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func testdataDir(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"..", "..", "..", "testdata", "walletconfig"}, parts...)...)
}

func exampleSource(t *testing.T) string { return testdataDir(t, "source") }

func goldenFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(testdataDir(t, "golden", name))
	require.NoError(t, err)
	return raw
}

func TestBuild_TheCommittedExampleBuildsTheGoldenPayload(t *testing.T) {
	config, err := loadSource(exampleSource(t), buildOptions{IssuedAt: goldenIssuedAt})
	require.NoError(t, err)

	built, err := configJSON(config)
	require.NoError(t, err)
	require.Equal(t, string(goldenFile(t, "config.json")), string(built))

	require.Equal(t, "yivi-golden", config.ID)
	require.Equal(t, uint64(1), config.Version)
	require.Len(t, config.TrustedEntities, 3)
	require.Equal(t, "golden-issuer-ca", config.TrustedEntities[0].ID, "entities follow directory-name order")
	require.Equal(t, "Golden Issuer Root CA", config.TrustedEntities[0].Handles[0].RootCertificate.Subject.CommonName)
	require.Equal(t, "golden-party", config.TrustedEntities[1].ID)
	require.Equal(t, "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", config.TrustedEntities[1].Logo.Digest,
		"the logo digest is computed from the file beside the entity")

	require.Equal(t, walletconfig.CurrentSchemaVersion, config.SchemaVersion)
	require.Len(t, config.CredentialCatalog, 2)
	require.Equal(t, "https://golden.example/vct/email", config.CredentialCatalog[0].VCT, "credentials follow directory-name order")
	require.True(t, config.CredentialCatalog[0].InStore)
	require.Len(t, config.CredentialCatalog[1].Offerings, 2)
}

func TestBuild_VersionComesFromTheFlagOverTheFile(t *testing.T) {
	config, err := loadSource(exampleSource(t), buildOptions{IssuedAt: goldenIssuedAt, Version: 7})
	require.NoError(t, err)
	require.Equal(t, uint64(7), config.Version)
}

// copyExample copies the committed example into a temp dir a test may edit.
func copyExample(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, filepath.WalkDir(exampleSource(t), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(exampleSource(t), path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(dir, relative), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, relative), data, 0o644)
	}))
	return dir
}

func rewriteFile(t *testing.T, path, old, new string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), old)
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(data), old, new, 1)), 0o644))
}

func TestBuild_RefusesWhatACuratorGetsWrong(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(dir string)
		want   string
	}{
		{"an unknown member in config.json", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "config.json"), `"version": 1,`, `"version": 1, "verison": 2,`)
		}, `unknown field "verison"`},
		{"an unknown member in entity.json", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-party", "entity.json"), `"roles":`, `"role": [], "roles":`)
		}, `unknown field "role"`},
		{"no version anywhere", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "config.json"), `"version": 1,`, ``)
		}, "no version"},
		{"a certificate file that is missing", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-verifier", "entity.json"), `"verifier.crt"`, `"missing.crt"`)
		}, "missing.crt"},
		{"a certificate outside the entity's directory", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-verifier", "entity.json"), `"verifier.crt"`, `"../golden-issuer-ca/root.crt"`)
		}, "bare filename"},
		{"an unknown handle type", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-party", "entity.json"), `"type": "did"`, `"type": "openid_federation"`)
		}, `unknown handle type "openid_federation"`},
		{"a logo with neither digest nor file", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-party", "entity.json"), `, "file": "party.png"`, ``)
		}, `"digest" or a "file"`},
		{"an entity the wallet would refuse", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "entities", "golden-party", "entity.json"), `"trust_level": "high"`, `"trust_level": "very_high"`)
		}, "does not validate"},
		{"no next_update_days", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "config.json"), `"next_update_days": 30,`, ``)
		}, "next_update_days"},
		{"an unknown member in credential.json", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "credentials", "email", "credential.json"), `"in_store": true,`, `"in_store": true, "instore": true,`)
		}, `unknown field "instore"`},
		{"a catalogue offering without a default url", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "credentials", "pid", "credential.json"), `"default": "https://pid.golden.example/start"`, `"nl": "https://pid.golden.example/start"`)
		}, `needs a "default" entry`},
		{"a catalogue entry listed twice", func(dir string) {
			rewriteFile(t, filepath.Join(dir, "credentials", "pid", "credential.json"), `"vct": "urn:eudi:pid:golden:1"`, `"vct": "https://golden.example/vct/email"`)
		}, "listed by another entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyExample(t)
			tc.mutate(dir)
			_, err := loadSource(dir, buildOptions{IssuedAt: goldenIssuedAt})
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestBuild_WithoutEntitiesIsAValidEmptyConfig(t *testing.T) {
	dir := copyExample(t)
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "entities")))
	config, err := loadSource(dir, buildOptions{IssuedAt: goldenIssuedAt})
	require.NoError(t, err)
	require.Empty(t, config.TrustedEntities)
}

// keygenAndSign runs the release sequence with a throwaway chain: keygen, build,
// sign against the root. Returns the signed config, the root path and the config.
func keygenAndSign(t *testing.T, version uint64, issuedAt time.Time, days int) (signed []byte, rootPath string, config *walletconfig.Config) {
	t.Helper()
	keys := t.TempDir()
	require.NoError(t, writeThrowawayChain(keys, "Yivi Test", days))

	config, err := loadSource(exampleSource(t), buildOptions{IssuedAt: issuedAt, Version: version})
	require.NoError(t, err)

	key, err := readSigningKey(filepath.Join(keys, "signer.key"))
	require.NoError(t, err)
	chain, err := readCertificateChain(filepath.Join(keys, "chain.pem"))
	require.NoError(t, err)
	require.Len(t, chain, 2, "leaf and intermediate, without the root")
	root, err := readCertificate(filepath.Join(keys, "root.crt"))
	require.NoError(t, err)

	signed, err = signConfig(config, key, chain, root)
	require.NoError(t, err)
	return signed, filepath.Join(keys, "root.crt"), config
}

func TestKeygenSignVerify_RoundTrip(t *testing.T) {
	signed, rootPath, config := keygenAndSign(t, 3, time.Now(), 1)
	root, err := readCertificate(rootPath)
	require.NoError(t, err)

	verified, err := walletconfig.Verify(signed, walletconfig.Environment{Name: "golden", ConfigID: "yivi-golden", SigningRoot: root}, time.Now())
	require.NoError(t, err)
	require.Equal(t, config.Version, verified.Config.Version)
	require.Equal(t, "throwaway-wallet-config-signer", verified.Signer.Subject.CommonName)

	other := t.TempDir()
	require.NoError(t, writeThrowawayChain(other, "Someone Else", 1))
	otherRoot, err := readCertificate(filepath.Join(other, "root.crt"))
	require.NoError(t, err)
	_, err = walletconfig.Verify(signed, walletconfig.Environment{Name: "golden", ConfigID: "yivi-golden", SigningRoot: otherRoot}, time.Now())
	require.ErrorContains(t, err, "unknown authority")
}

func TestSign_RefusesAChainThatDoesNotReachTheRoot(t *testing.T) {
	keys, other := t.TempDir(), t.TempDir()
	require.NoError(t, writeThrowawayChain(keys, "Yivi Test", 1))
	require.NoError(t, writeThrowawayChain(other, "Someone Else", 1))
	config, err := loadSource(exampleSource(t), buildOptions{IssuedAt: time.Now(), Version: 1})
	require.NoError(t, err)
	key, err := readSigningKey(filepath.Join(keys, "signer.key"))
	require.NoError(t, err)
	chain, err := readCertificateChain(filepath.Join(keys, "chain.pem"))
	require.NoError(t, err)
	otherRoot, err := readCertificate(filepath.Join(other, "root.crt"))
	require.NoError(t, err)

	_, err = signConfig(config, key, chain, otherRoot)
	require.ErrorContains(t, err, "the signed config does not verify")

	// Without a root the chain is not checked, and signing succeeds.
	_, err = signConfig(config, key, chain, nil)
	require.NoError(t, err)
}

// runConfigCommand executes `yivi eudi config <args>` and returns stdout.
func runConfigCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	EudiRootCmd.SetOut(&out)
	EudiRootCmd.SetErr(&out)
	EudiRootCmd.SetArgs(append([]string{"config"}, args...))
	err := EudiRootCmd.Execute()
	return out.String(), err
}

func TestCommands_BuildSignVerifyShow(t *testing.T) {
	work := t.TempDir()
	built := filepath.Join(work, "config.json")
	signed := filepath.Join(work, "config.jws")

	_, err := runConfigCommand(t, "keygen", "--out-dir", filepath.Join(work, "keys"), "--days", "1")
	require.NoError(t, err)

	_, err = runConfigCommand(t, "build", exampleSource(t), "--version", "5", "-o", built)
	require.NoError(t, err)
	_, err = runConfigCommand(t, "sign", built,
		"--key", filepath.Join(work, "keys", "signer.key"),
		"--cert", filepath.Join(work, "keys", "chain.pem"),
		"--root", filepath.Join(work, "keys", "root.crt"),
		"-o", signed)
	require.NoError(t, err)

	out, err := runConfigCommand(t, "verify", signed,
		"--root", filepath.Join(work, "keys", "root.crt"),
		"--environment", "golden", "--id", "yivi-golden", "--json")
	require.NoError(t, err)
	require.Contains(t, out, `"version": 5`)

	_, err = runConfigCommand(t, "verify", signed,
		"--root", filepath.Join(work, "keys", "root.crt"),
		"--environment", "staging", "--id", "yivi-golden")
	require.ErrorContains(t, err, `for environment "golden", expected "staging"`)

	out, err = runConfigCommand(t, "show", signed)
	require.NoError(t, err)
	require.Contains(t, out, "UNVERIFIED")
	require.Contains(t, out, "id:                yivi-golden")
	require.Contains(t, out, "golden-verifier (Golden Verifier): verifier, medium")
	require.Contains(t, out, "may request: https://golden.example/vct/email (email)")
	require.Contains(t, out, "credential catalog: 2")
	require.Contains(t, out, "https://golden.example/vct/email (1 offering(s), in store)")
	require.Contains(t, out, "issue at https://issue.golden.example/email (+1 language(s)), issuer https://issuer.golden.example")

	out, err = runConfigCommand(t, "show", built, "--json")
	require.NoError(t, err)
	builtRaw, err := os.ReadFile(built)
	require.NoError(t, err)
	require.Equal(t, string(builtRaw), out, "show --json prints what build wrote")
}

// The release gate: a candidate must be a later issue than the published config.
func TestVerify_AgainstThePublishedConfig(t *testing.T) {
	keys := t.TempDir()
	require.NoError(t, writeThrowawayChain(keys, "Yivi Test", 1))
	key, err := readSigningKey(filepath.Join(keys, "signer.key"))
	require.NoError(t, err)
	chain, err := readCertificateChain(filepath.Join(keys, "chain.pem"))
	require.NoError(t, err)
	root, err := readCertificate(filepath.Join(keys, "root.crt"))
	require.NoError(t, err)
	sign := func(version uint64, issuedAt time.Time) []byte {
		config, err := loadSource(exampleSource(t), buildOptions{IssuedAt: issuedAt, Version: version})
		require.NoError(t, err)
		signed, err := signConfig(config, key, chain, root)
		require.NoError(t, err)
		return signed
	}
	now := time.Now().Truncate(time.Second)
	published := sign(2, now.Add(-time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(published) }))
	t.Cleanup(server.Close)

	env := walletconfig.Environment{Name: "golden", ConfigID: "yivi-golden", SigningRoot: root}
	verifiedOf := func(signed []byte) *walletconfig.Config {
		verified, err := walletconfig.Verify(signed, env, now)
		require.NoError(t, err)
		return verified.Config
	}

	require.NoError(t, compareToPublished(t.Context(), server.URL, env, now, verifiedOf(sign(3, now))), "a higher version advances")
	require.NoError(t, compareToPublished(t.Context(), server.URL, env, now, verifiedOf(sign(2, now))), "a re-issue of the same version advances")
	require.ErrorContains(t, compareToPublished(t.Context(), server.URL, env, now, verifiedOf(published)), "does not advance")
	require.ErrorContains(t, compareToPublished(t.Context(), server.URL, env, now, verifiedOf(sign(1, now))), "build with --version 3")

	// Through the command, with the file and the URL.
	work := t.TempDir()
	candidate := filepath.Join(work, "candidate.jws")
	require.NoError(t, os.WriteFile(candidate, sign(3, now), 0o644))
	_, err = runConfigCommand(t, "verify", candidate, "--root", filepath.Join(keys, "root.crt"),
		"--environment", "golden", "--id", "yivi-golden", "--against", server.URL)
	require.NoError(t, err)

	// And the published config on its own.
	_, err = runConfigCommand(t, "verify", "--root", filepath.Join(keys, "root.crt"),
		"--environment", "golden", "--id", "yivi-golden", "--against", server.URL)
	require.NoError(t, err)
}

func TestVerify_RefusesAnExpiredConfigAndReportsFreshness(t *testing.T) {
	// A signer that outlives the config's grace period, so what expires is the
	// config and not the chain.
	signed, rootPath, config := keygenAndSign(t, 1, time.Now(), 60)
	work := t.TempDir()
	path := filepath.Join(work, "config.jws")
	require.NoError(t, os.WriteFile(path, signed, 0o644))

	expired := config.ExpiresAt().Add(time.Hour).UTC().Format(time.RFC3339)
	_, err := runConfigCommand(t, "verify", path, "--root", rootPath, "--at", expired)
	require.ErrorContains(t, err, "past its grace period")
}

func TestShow_ReadsTheGoldenSignedConfig(t *testing.T) {
	config, signed, err := decodeConfigFile(goldenFile(t, "config.jws"))
	require.NoError(t, err)
	require.True(t, signed)
	require.Equal(t, "yivi-golden", config.ID)
	require.Equal(t, clientmodels.TrustLevel_Medium, config.Policy.MinimumTrustLevel.Disclosure)

	config, signed, err = decodeConfigFile(goldenFile(t, "config.json"))
	require.NoError(t, err)
	require.False(t, signed)
	require.Len(t, config.TrustedEntities, 3)

	_, _, err = decodeConfigFile([]byte("garbage"))
	require.Error(t, err)
}

func TestServe_ServesTheFileOnEveryPath(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, "config.jws")
	require.NoError(t, os.WriteFile(path, []byte("first"), 0o644))
	server := httptest.NewServer(serveConfigHandler(path))
	t.Cleanup(server.Close)

	for _, route := range []string{"/", "/wallet-config/v1/"} {
		response, err := http.Get(server.URL + route)
		require.NoError(t, err)
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		require.Equal(t, "first", string(body))
		require.Equal(t, "application/jwt", response.Header.Get("Content-Type"))
	}

	// Re-read per request, so replacing the file changes what is served.
	require.NoError(t, os.WriteFile(path, []byte("second"), 0o644))
	response, err := http.Get(server.URL + "/")
	require.NoError(t, err)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.Equal(t, "second", string(body))
}

func TestKeygen_WritesAChainTheSignerCanUse(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeThrowawayChain(dir, "Yivi Test", 2))
	for _, name := range []string{"root.crt", "root.key", "ca.crt", "ca.key", "signer.crt", "signer.key", "chain.pem"} {
		require.FileExists(t, filepath.Join(dir, name))
	}
	chain, err := readCertificateChain(filepath.Join(dir, "chain.pem"))
	require.NoError(t, err)
	require.Equal(t, "throwaway-wallet-config-signer", chain[0].Subject.CommonName)
	require.Equal(t, "Throwaway Wallet Config CA", chain[1].Subject.CommonName)
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	require.NoError(t, err)
	require.True(t, root.IsCA)
	require.NoError(t, chain[1].CheckSignatureFrom(root))
	require.NoError(t, chain[0].CheckSignatureFrom(chain[1]))
}
