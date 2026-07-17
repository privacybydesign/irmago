package dnssec

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// testZone is a DNSSEC-signed zone with a single key used as both KSK and ZSK.
type testZone struct {
	name   string
	dnskey *dns.DNSKEY
	signer crypto.Signer
}

func newTestZone(t *testing.T, name string) *testZone {
	t.Helper()
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := dnskey.Generate(256)
	require.NoError(t, err)
	return &testZone{name: name, dnskey: dnskey, signer: priv.(crypto.Signer)}
}

func (z *testZone) ds() *dns.DS {
	return z.dnskey.ToDS(dns.SHA256)
}

// sign produces an RRSIG over the RRset with the zone's key. A negative
// lifetime produces an already-expired signature.
func (z *testZone) sign(t *testing.T, rrset []dns.RR, lifetime time.Duration) *dns.RRSIG {
	t.Helper()
	now := time.Now()
	inception := now.Add(-time.Hour)
	expiration := now.Add(lifetime)
	if lifetime < 0 {
		inception = now.Add(2 * lifetime)
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   z.dnskey.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      z.dnskey.KeyTag(),
		SignerName:  z.name,
	}
	require.NoError(t, sig.Sign(z.signer, rrset))
	return sig
}

// testResolver is a fake recursive resolver serving canned answers.
type testResolver struct {
	answers   map[recordKey][]dns.RR
	authority map[recordKey][]dns.RR
	addr      string
}

func newTestResolver(t *testing.T) *testResolver {
	t.Helper()
	resolver := &testResolver{
		answers:   map[recordKey][]dns.RR{},
		authority: map[recordKey][]dns.RR{},
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: resolver}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	resolver.addr = pc.LocalAddr().String()
	return resolver
}

func (r *testResolver) serve(name string, qtype uint16, answer ...dns.RR) {
	r.answers[recordKey{name, qtype}] = answer
}

func (r *testResolver) serveAuthority(name string, qtype uint16, ns ...dns.RR) {
	r.authority[recordKey{name, qtype}] = ns
}

func (r *testResolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	question := req.Question[0]
	key := recordKey{question.Name, question.Qtype}
	resp.Answer = r.answers[key]
	resp.Ns = r.authority[key]
	_ = w.WriteMsg(resp)
}

// testChain is a root → tld → leaf zone hierarchy served by a fake resolver.
type testChain struct {
	resolver *testResolver
	root     *testZone
	tld      *testZone
	leaf     *testZone
	verifier *ChainVerifier
}

const (
	testHost = "did.yivi.test."
	leafZone = "yivi.test."
	tldZone  = "test."
)

// newTestChain builds a fully signed hierarchy for did.yivi.test.
// Individual tests override served records to create failure scenarios.
func newTestChain(t *testing.T) *testChain {
	t.Helper()
	chain := &testChain{
		resolver: newTestResolver(t),
		root:     newTestZone(t, "."),
		tld:      newTestZone(t, tldZone),
		leaf:     newTestZone(t, leafZone),
	}

	// Root zone: self-signed DNSKEY, anchored via the verifier's trust anchors.
	rootKeys := []dns.RR{chain.root.dnskey}
	chain.resolver.serve(".", dns.TypeDNSKEY, chain.root.dnskey, chain.root.sign(t, rootKeys, time.Hour))

	// TLD: DNSKEY self-signed, DS signed by the root.
	tldKeys := []dns.RR{chain.tld.dnskey}
	chain.resolver.serve(tldZone, dns.TypeDNSKEY, chain.tld.dnskey, chain.tld.sign(t, tldKeys, time.Hour))
	tldDS := []dns.RR{chain.tld.ds()}
	chain.resolver.serve(tldZone, dns.TypeDS, chain.tld.ds(), chain.root.sign(t, tldDS, time.Hour))

	// Leaf zone: DNSKEY self-signed, DS signed by the TLD.
	leafKeys := []dns.RR{chain.leaf.dnskey}
	chain.resolver.serve(leafZone, dns.TypeDNSKEY, chain.leaf.dnskey, chain.leaf.sign(t, leafKeys, time.Hour))
	leafDS := []dns.RR{chain.leaf.ds()}
	chain.resolver.serve(leafZone, dns.TypeDS, chain.leaf.ds(), chain.tld.sign(t, leafDS, time.Hour))

	// The host's address record, signed by the leaf zone.
	chain.serveHostA(t, time.Hour)

	chain.verifier = &ChainVerifier{
		Servers:      []string{chain.resolver.addr},
		TrustAnchors: []*dns.DS{chain.root.ds()},
		Timeout:      2 * time.Second,
	}
	return chain
}

func (c *testChain) hostA() []dns.RR {
	return []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: testHost, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}}
}

func (c *testChain) serveHostA(t *testing.T, lifetime time.Duration) {
	rrset := c.hostA()
	c.resolver.serve(testHost, dns.TypeA, append(rrset, c.leaf.sign(t, rrset, lifetime))...)
}

func Test_Verify_FullChainValidates_ReturnsSecure(t *testing.T) {
	chain := newTestChain(t)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusSecure, result.Status, result.Detail)
}

func Test_Verify_UnsignedDelegation_ReturnsInsecure(t *testing.T) {
	chain := newTestChain(t)
	// The TLD serves no DS for the leaf zone: an unsigned delegation. The
	// leaf's records then carry no signatures either.
	chain.resolver.serve(leafZone, dns.TypeDS)
	chain.resolver.serve(testHost, dns.TypeA, chain.hostA()...)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: leafZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + leafZone, Mbox: "hostmaster." + leafZone}
	chain.resolver.serveAuthority(testHost, dns.TypeSOA, soa)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusInsecure, result.Status, result.Detail)
}

func Test_Verify_CompletelyUnsignedZone_ReturnsInsecure(t *testing.T) {
	chain := newTestChain(t)
	// A zone without DNSSEC at all: no DS and no DNSKEY records (e.g. google.com).
	chain.resolver.serve(leafZone, dns.TypeDS)
	chain.resolver.serve(leafZone, dns.TypeDNSKEY)
	chain.resolver.serve(testHost, dns.TypeA, chain.hostA()...)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: leafZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + leafZone, Mbox: "hostmaster." + leafZone}
	chain.resolver.serveAuthority(testHost, dns.TypeSOA, soa)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusInsecure, result.Status, result.Detail)
}

func Test_Verify_TamperedRecord_ReturnsBogus(t *testing.T) {
	chain := newTestChain(t)
	// Replace the host's address after signing, keeping the original RRSIG.
	original := chain.hostA()
	sig := chain.leaf.sign(t, original, time.Hour)
	tampered := &dns.A{
		Hdr: dns.RR_Header{Name: testHost, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("198.51.100.66"),
	}
	chain.resolver.serve(testHost, dns.TypeA, tampered, sig)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusBogus, result.Status, result.Detail)
}

func Test_Verify_StrippedSignatureInSignedZone_ReturnsBogus(t *testing.T) {
	chain := newTestChain(t)
	// The answer carries no RRSIG although the zone has a valid chain of trust.
	chain.resolver.serve(testHost, dns.TypeA, chain.hostA()...)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: leafZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + leafZone, Mbox: "hostmaster." + leafZone}
	chain.resolver.serveAuthority(testHost, dns.TypeSOA, soa)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusBogus, result.Status, result.Detail)
}

func Test_Verify_ExpiredSignature_ReturnsBogus(t *testing.T) {
	chain := newTestChain(t)
	chain.serveHostA(t, -time.Hour)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusBogus, result.Status, result.Detail)
}

func Test_Verify_TamperedDS_ReturnsBogus(t *testing.T) {
	chain := newTestChain(t)
	// The delegation points at a different key than the leaf zone uses.
	otherZone := newTestZone(t, leafZone)
	forgedDS := []dns.RR{otherZone.ds()}
	chain.resolver.serve(leafZone, dns.TypeDS, otherZone.ds(), chain.tld.sign(t, forgedDS, time.Hour))

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusBogus, result.Status, result.Detail)
}

func Test_Verify_SelfSignedDS_ReturnsBogus(t *testing.T) {
	chain := newTestChain(t)
	// A zone trying to forge its own chain of trust: DS signed by the child
	// zone itself instead of the parent.
	rogue := newTestZone(t, leafZone)
	rogueDS := []dns.RR{rogue.ds()}
	chain.resolver.serve(leafZone, dns.TypeDS, rogue.ds(), rogue.sign(t, rogueDS, time.Hour))
	rogueKeys := []dns.RR{rogue.dnskey}
	chain.resolver.serve(leafZone, dns.TypeDNSKEY, rogue.dnskey, rogue.sign(t, rogueKeys, time.Hour))
	chain.resolver.serve(testHost, dns.TypeA, append(chain.hostA(), rogue.sign(t, chain.hostA(), time.Hour))...)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusBogus, result.Status, result.Detail)
}

func Test_Verify_CnameToUnsignedZone_ReturnsInsecure(t *testing.T) {
	chain := newTestChain(t)
	// The host is a CNAME (signed) pointing into a zone without DNSSEC.
	target := "cdn.elsewhere.example."
	cname := []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: testHost, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: target,
	}}
	targetA := &dns.A{
		Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.2"),
	}
	chain.resolver.serve(testHost, dns.TypeA, append(cname, chain.leaf.sign(t, cname, time.Hour), targetA)...)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "elsewhere.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.elsewhere.example.", Mbox: "hostmaster.elsewhere.example."}
	chain.resolver.serveAuthority(target, dns.TypeSOA, soa)
	chain.resolver.serve("elsewhere.example.", dns.TypeDS)
	unsignedKeys := newTestZone(t, "elsewhere.example.")
	chain.resolver.serve("elsewhere.example.", dns.TypeDNSKEY, unsignedKeys.dnskey, unsignedKeys.sign(t, []dns.RR{unsignedKeys.dnskey}, time.Hour))

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusInsecure, result.Status, result.Detail)
}

func Test_Verify_ResolverUnreachable_ReturnsIndeterminate(t *testing.T) {
	verifier := &ChainVerifier{
		Servers: []string{"127.0.0.1:1"},
		Timeout: 200 * time.Millisecond,
	}

	result := verifier.Verify("did.yivi.test")
	require.Equal(t, StatusIndeterminate, result.Status, result.Detail)
}

func Test_Verify_IPAddress_ReturnsIndeterminate(t *testing.T) {
	verifier := &ChainVerifier{}

	result := verifier.Verify("192.0.2.1")
	require.Equal(t, StatusIndeterminate, result.Status, result.Detail)
}

func Test_Verify_IPv6OnlyHost_ValidatesAAAA(t *testing.T) {
	chain := newTestChain(t)
	chain.resolver.serve(testHost, dns.TypeA)
	aaaa := []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: testHost, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	chain.resolver.serve(testHost, dns.TypeAAAA, append(aaaa, chain.leaf.sign(t, aaaa, time.Hour))...)

	result := chain.verifier.Verify("did.yivi.test")
	require.Equal(t, StatusSecure, result.Status, result.Detail)
}
