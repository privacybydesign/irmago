package trust

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/stretchr/testify/require"
)

// poolValidator is a ChainValidator over a fixed set of anchors, standing in
// for the wallet's trust model.
type poolValidator struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	installed     []*x509.Certificate
}

func newPoolValidator(roots []*x509.Certificate, intermediates ...*x509.Certificate) *poolValidator {
	v := &poolValidator{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	for _, root := range roots {
		v.roots.AddCert(root)
	}
	for _, intermediate := range intermediates {
		v.intermediates.AddCert(intermediate)
	}
	return v
}

func (v *poolValidator) ValidateChain(leaf *x509.Certificate) ([][]*x509.Certificate, error) {
	return leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: v.intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
}

func (v *poolValidator) InstalledAnchor(root *x509.Certificate) bool {
	for _, installed := range v.installed {
		if installed.Equal(root) {
			return true
		}
	}
	return false
}

// pki is a CA hierarchy a test anchors and issues under.
type pki struct {
	rootKey *ecdsa.PrivateKey
	root    *x509.Certificate
	caKey   *ecdsa.PrivateKey
	ca      *x509.Certificate
}

func newPKI(t *testing.T, name string) *pki {
	t.Helper()
	rootKey, root := walletconfig.NewTestCA(t, name+" Root", nil, nil)
	caKey, ca := walletconfig.NewTestCA(t, name+" CA", root, rootKey)
	return &pki{rootKey: rootKey, root: root, caKey: caKey, ca: ca}
}

// leaf issues an end-entity certificate under the intermediate CA.
func (p *pki) leaf(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	_, leaf := walletconfig.NewTestEndEntity(t, name, p.ca, p.caKey, nil)
	return leaf
}

// leafUnderRoot issues an end-entity certificate directly under the root.
func (p *pki) leafUnderRoot(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	_, leaf := walletconfig.NewTestEndEntity(t, name, p.root, p.rootKey, nil)
	return leaf
}

func caEntity(id string, level clientmodels.TrustLevel, root *x509.Certificate, intermediates ...*x509.Certificate) walletconfig.TrustedEntity {
	handle := walletconfig.Handle{Type: walletconfig.HandleTypeX509CA, RootCertificate: &walletconfig.Certificate{Certificate: root}}
	for _, intermediate := range intermediates {
		handle.Intermediates = append(handle.Intermediates, walletconfig.Certificate{Certificate: intermediate})
	}
	return walletconfig.TrustedEntity{
		ID:         id,
		Name:       clientmodels.TranslatedString{"en": id},
		Roles:      []walletconfig.Role{walletconfig.RoleIssuer, walletconfig.RoleVerifier},
		TrustLevel: level,
		Handles:    []walletconfig.Handle{handle},
	}
}

func didEntity(id string, level clientmodels.TrustLevel, did string, roles ...walletconfig.Role) walletconfig.TrustedEntity {
	if len(roles) == 0 {
		roles = []walletconfig.Role{walletconfig.RoleIssuer, walletconfig.RoleVerifier}
	}
	return walletconfig.TrustedEntity{
		ID:         id,
		Name:       clientmodels.TranslatedString{"en": id},
		Roles:      roles,
		TrustLevel: level,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: did}},
	}
}

func certEntity(id string, level clientmodels.TrustLevel, certificate *x509.Certificate) walletconfig.TrustedEntity {
	return walletconfig.TrustedEntity{
		ID:         id,
		Name:       clientmodels.TranslatedString{"en": id},
		Roles:      []walletconfig.Role{walletconfig.RoleIssuer, walletconfig.RoleVerifier},
		TrustLevel: level,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeX509Cert, Certificate: &walletconfig.Certificate{Certificate: certificate}}},
	}
}

// snapshotWith is a fresh config carrying the entities, in an environment with
// no built-in ones.
func snapshotWith(entities ...walletconfig.TrustedEntity) walletconfig.Snapshot {
	config := walletconfig.NewTestConfig("test", 1, time.Now())
	config.TrustedEntities = entities
	return walletconfig.Snapshot{
		Environment: walletconfig.Environment{Name: "test"},
		Config:      config,
		Freshness:   walletconfig.Fresh,
	}
}

func TestView_NothingMatchesRanksLow(t *testing.T) {
	p := newPKI(t, "Unknown")
	view := NewView(snapshotWith(), newPoolValidator(nil), newPoolValidator(nil), 0)

	verdict := view.Verifier(Evidence{Certificate: p.leaf(t, "stranger")})
	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)
	require.False(t, verdict.Anchored)
	require.Nil(t, verdict.Entity)
	require.False(t, verdict.IsVouchedFor())

	verdict = view.Issuer(Evidence{DID: "did:web:stranger.example"})
	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)

	verdict = view.Issuer(Evidence{})
	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level, "no evidence at all is still low, never unevaluated")
}

func TestView_ChainToAListedCAConfersTheCAsLevel(t *testing.T) {
	p := newPKI(t, "Listed")
	entity := caEntity("listed-ca", clientmodels.TrustLevel_Medium, p.root, p.ca)
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	view := NewView(snapshotWith(entity), validator, validator, 0)

	verdict := view.Issuer(Evidence{Certificate: p.leaf(t, "issuer.example")})
	require.Equal(t, clientmodels.TrustLevel_Medium, verdict.Level)
	require.True(t, verdict.Anchored)
	require.Equal(t, "listed-ca", verdict.Entity.ID)
	require.Len(t, verdict.Chain, 3, "leaf, intermediate, root")
}

// Two entities under one root are told apart by the intermediate each names.
func TestView_SharedRootIsToldApartByIntermediate(t *testing.T) {
	rootKey, root := walletconfig.NewTestCA(t, "Shared Root", nil, nil)
	aKey, aCA := walletconfig.NewTestCA(t, "Org A CA", root, rootKey)
	bKey, bCA := walletconfig.NewTestCA(t, "Org B CA", root, rootKey)
	_, aLeaf := walletconfig.NewTestEndEntity(t, "a.example", aCA, aKey, nil)
	_, bLeaf := walletconfig.NewTestEndEntity(t, "b.example", bCA, bKey, nil)
	_, directLeaf := walletconfig.NewTestEndEntity(t, "direct.example", root, rootKey, nil)

	validator := newPoolValidator([]*x509.Certificate{root}, aCA, bCA)
	view := NewView(snapshotWith(
		caEntity("org-a", clientmodels.TrustLevel_High, root, aCA),
		caEntity("org-b", clientmodels.TrustLevel_Medium, root, bCA),
	), validator, validator, 0)

	require.Equal(t, "org-a", view.Issuer(Evidence{Certificate: aLeaf}).Entity.ID)
	require.Equal(t, clientmodels.TrustLevel_High, view.Issuer(Evidence{Certificate: aLeaf}).Level)
	require.Equal(t, "org-b", view.Issuer(Evidence{Certificate: bLeaf}).Entity.ID)
	require.Equal(t, clientmodels.TrustLevel_Medium, view.Issuer(Evidence{Certificate: bLeaf}).Level)

	// A leaf directly under the shared root passes through neither named
	// intermediate: anchored, but no entity vouches for it.
	direct := view.Issuer(Evidence{Certificate: directLeaf})
	require.True(t, direct.Anchored)
	require.Nil(t, direct.Entity)
	require.Equal(t, clientmodels.TrustLevel_Low, direct.Level)
}

// A handle that names only a root anchors the whole subtree.
func TestView_RootOnlyHandleAnchorsTheSubtree(t *testing.T) {
	p := newPKI(t, "Wide")
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	view := NewView(snapshotWith(caEntity("wide", clientmodels.TrustLevel_High, p.root)), validator, validator, 0)

	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{Certificate: p.leaf(t, "under-ca")}).Level)
	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{Certificate: p.leafUnderRoot(t, "under-root")}).Level)
}

func TestView_RolesAreSeparateGrants(t *testing.T) {
	p := newPKI(t, "Issuers")
	entity := caEntity("issuers-only", clientmodels.TrustLevel_High, p.root, p.ca)
	entity.Roles = []walletconfig.Role{walletconfig.RoleIssuer}
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	view := NewView(snapshotWith(entity), validator, validator, 0)
	leaf := p.leaf(t, "party.example")

	require.Equal(t, clientmodels.TrustLevel_High, view.Issuer(Evidence{Certificate: leaf}).Level)
	asVerifier := view.Verifier(Evidence{Certificate: leaf})
	require.Equal(t, clientmodels.TrustLevel_Low, asVerifier.Level, "an issuer entity grants nothing to a verifier")
	require.True(t, asVerifier.Anchored, "the chain still validates against the verifier pool this test shares")
}

func TestView_ExactCertificateAndDIDHandles(t *testing.T) {
	p := newPKI(t, "Unanchored")
	leaf := p.leaf(t, "party.example")
	other := p.leaf(t, "other.example")
	view := NewView(snapshotWith(
		certEntity("by-cert", clientmodels.TrustLevel_High, leaf),
		didEntity("by-did", clientmodels.TrustLevel_Medium, "did:web:party.example"),
	), newPoolValidator(nil), newPoolValidator(nil), 0)

	byCert := view.Verifier(Evidence{Certificate: leaf})
	require.Equal(t, clientmodels.TrustLevel_High, byCert.Level)
	require.False(t, byCert.Anchored, "listed, not anchored: the chain validates nowhere")
	require.Equal(t, "by-cert", byCert.Entity.ID)

	require.Equal(t, clientmodels.TrustLevel_Low, view.Verifier(Evidence{Certificate: other}).Level)

	require.Equal(t, clientmodels.TrustLevel_Medium, view.Issuer(Evidence{DID: "did:web:party.example"}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{DID: "did:web:party.example:sub"}).Level, "exact match, no prefixes")
}

// Effective level is the strongest across matching entities: chaining to a CA
// and being listed individually both count, whichever is higher wins.
func TestView_EffectiveLevelIsTheMaximum(t *testing.T) {
	p := newPKI(t, "Listed")
	leaf := p.leaf(t, "party.example")
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)

	view := NewView(snapshotWith(
		caEntity("ca", clientmodels.TrustLevel_Medium, p.root, p.ca),
		certEntity("party", clientmodels.TrustLevel_High, leaf),
	), validator, validator, 0)
	verdict := view.Issuer(Evidence{Certificate: leaf})
	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level)
	require.Equal(t, "party", verdict.Entity.ID)
	require.True(t, verdict.Anchored)

	view = NewView(snapshotWith(
		caEntity("ca", clientmodels.TrustLevel_High, p.root, p.ca),
		certEntity("party", clientmodels.TrustLevel_Low, leaf),
	), validator, validator, 0)
	verdict = view.Issuer(Evidence{Certificate: leaf})
	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level)
	require.Equal(t, "ca", verdict.Entity.ID, "a listing never pulls a certified party down")
}

// Once the config is expired its individual listings stop counting; its CA
// anchors keep working.
func TestView_ExpiredConfigKeepsCAAnchorsAndDropsListings(t *testing.T) {
	p := newPKI(t, "Listed")
	leaf := p.leaf(t, "party.example")
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	snapshot := snapshotWith(
		caEntity("ca", clientmodels.TrustLevel_Medium, p.root, p.ca),
		certEntity("party", clientmodels.TrustLevel_High, leaf),
		didEntity("did-party", clientmodels.TrustLevel_High, "did:web:party.example"),
	)

	for _, freshness := range []walletconfig.Freshness{walletconfig.Fresh, walletconfig.Stale} {
		snapshot.Freshness = freshness
		view := NewView(snapshot, validator, validator, 0)
		require.Equal(t, clientmodels.TrustLevel_High, view.Issuer(Evidence{Certificate: leaf}).Level, "%s", freshness)
		require.Equal(t, clientmodels.TrustLevel_High, view.Issuer(Evidence{DID: "did:web:party.example"}).Level, "%s", freshness)
	}

	snapshot.Freshness = walletconfig.Expired
	view := NewView(snapshot, validator, validator, 0)
	require.Equal(t, clientmodels.TrustLevel_Medium, view.Issuer(Evidence{Certificate: leaf}).Level, "the CA anchor still confers its level")
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{DID: "did:web:party.example"}).Level, "the listing no longer counts")
	require.Equal(t, walletconfig.Expired, view.Freshness())
}

// Built-in entities are compiled in and count whatever the config's state.
func TestView_BuiltinEntitiesAlwaysCount(t *testing.T) {
	p := newPKI(t, "Builtin")
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	snapshot := walletconfig.Snapshot{
		Environment: walletconfig.Environment{
			Name:            "test",
			BuiltinEntities: []walletconfig.TrustedEntity{didEntity("builtin", clientmodels.TrustLevel_High, "did:web:builtin.example")},
		},
	}
	view := NewView(snapshot, validator, validator, 0)
	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{DID: "did:web:builtin.example"}).Level)
	require.Equal(t, walletconfig.DefaultPolicy(), view.Policy(), "without a config the default policy applies")

	snapshot.Config = walletconfig.NewTestConfig("test", 1, time.Now())
	snapshot.Freshness = walletconfig.Expired
	view = NewView(snapshot, validator, validator, 0)
	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{DID: "did:web:builtin.example"}).Level,
		"an expired config does not touch what is compiled in")
}

// An anchor installed locally stands in for a CA the config would list: what
// chains to it ranks high, as under Yivi's own CA.
func TestView_LocallyInstalledAnchorRanksHigh(t *testing.T) {
	p := newPKI(t, "Installed")
	validator := newPoolValidator([]*x509.Certificate{p.root}, p.ca)
	validator.installed = []*x509.Certificate{p.root}
	view := NewView(snapshotWith(), validator, validator, 0)

	verdict := view.Issuer(Evidence{Certificate: p.leaf(t, "issuer.example")})
	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level)
	require.True(t, verdict.Anchored)
	require.Nil(t, verdict.Entity, "no entity vouches; the installed anchor does")
}

func TestView_ChainValidationIsMemoizedPerView(t *testing.T) {
	p := newPKI(t, "Counted")
	validator := &countingValidator{poolValidator: newPoolValidator([]*x509.Certificate{p.root}, p.ca)}
	view := NewView(snapshotWith(caEntity("ca", clientmodels.TrustLevel_High, p.root, p.ca)), validator, validator, 0)
	leaf := p.leaf(t, "issuer.example")

	for range 5 {
		view.Issuer(Evidence{Certificate: leaf})
	}
	require.Equal(t, 1, validator.calls, "one issuer asked about five times builds one chain")
	view.Verifier(Evidence{Certificate: leaf})
	require.Equal(t, 2, validator.calls, "the roles consult separate anchor sets")
}

type countingValidator struct {
	*poolValidator
	calls int
}

func (v *countingValidator) ValidateChain(leaf *x509.Certificate) ([][]*x509.Certificate, error) {
	v.calls++
	return v.poolValidator.ValidateChain(leaf)
}

func TestView_AppUpdateRequired(t *testing.T) {
	snapshot := snapshotWith()
	snapshot.Config.MinimumAppBuild = 100

	require.True(t, NewView(snapshot, nil, nil, 99).AppUpdateRequired())
	require.False(t, NewView(snapshot, nil, nil, 100).AppUpdateRequired())
	require.False(t, NewView(snapshot, nil, nil, 0).AppUpdateRequired(), "a build that does not know its number is not gated")
	require.False(t, NewView(walletconfig.Snapshot{}, nil, nil, 1).AppUpdateRequired(), "no config, no minimum")
}

func TestCheckMinimum(t *testing.T) {
	policy := walletconfig.Policy{MinimumTrustLevel: walletconfig.MinimumTrustLevel{
		Issuance:   clientmodels.TrustLevel_Low,
		Disclosure: clientmodels.TrustLevel_Medium,
	}}

	require.NoError(t, CheckMinimum(policy, SessionIssuance, clientmodels.TrustLevel_Low))
	require.NoError(t, CheckMinimum(policy, SessionDisclosure, clientmodels.TrustLevel_Medium))
	require.NoError(t, CheckMinimum(policy, SessionDisclosure, clientmodels.TrustLevel_High))

	err := CheckMinimum(policy, SessionDisclosure, clientmodels.TrustLevel_Low)
	require.True(t, errors.Is(err, ErrBelowMinimumTrustLevel))
	require.ErrorContains(t, err, "disclosure requires at least medium")

	require.Error(t, CheckMinimum(policy, SessionIssuance, clientmodels.TrustLevel_Unevaluated), "unevaluated ranks below every rung")
}

func TestRankAndStronger(t *testing.T) {
	require.True(t, Stronger(clientmodels.TrustLevel_High, clientmodels.TrustLevel_Medium))
	require.True(t, Stronger(clientmodels.TrustLevel_Medium, clientmodels.TrustLevel_Low))
	require.True(t, Stronger(clientmodels.TrustLevel_Low, clientmodels.TrustLevel_Unevaluated))
	require.False(t, Stronger(clientmodels.TrustLevel_Low, clientmodels.TrustLevel_Low))
	require.Equal(t, 0, Rank("very_high"), "an unknown level ranks as unevaluated")
}

func TestVerdict_Constraints(t *testing.T) {
	entity := didEntity("constrained", clientmodels.TrustLevel_High, "did:web:party.example")
	entity.Constraints = &walletconfig.Constraints{
		Issuance: &walletconfig.IssuanceConstraint{AllowedCredentials: []string{"https://party.example/vct/email"}},
	}
	view := NewView(snapshotWith(entity), nil, nil, 0)

	verdict := view.Issuer(Evidence{DID: "did:web:party.example"})
	require.Equal(t, []string{"https://party.example/vct/email"}, verdict.IssuanceConstraint().AllowedCredentials)
	require.Nil(t, verdict.DisclosureConstraint())

	require.Nil(t, view.Issuer(Evidence{DID: "did:web:other.example"}).IssuanceConstraint(), "no entity, no constraint")
}
