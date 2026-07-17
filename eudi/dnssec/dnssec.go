// Package dnssec provides a DNSSEC chain-of-trust check for host names.
//
// The verifier queries a recursive resolver with the DO and CD bits set and
// validates all signatures itself, from the configured trust anchors (by
// default the IANA root anchors) down to the host's address records. The
// resolver's AD bit is deliberately not trusted: on untrusted networks the
// path to the resolver is exactly what an attacker controls.
//
// The check is advisory: it distinguishes domains where DNSSEC validation
// fails (possible spoofing) from domains that simply are not signed, so
// callers can surface a warning instead of failing the operation.
//
// Limitations: absence of a DS record set is taken at face value (no NSEC/
// NSEC3 denial-of-existence validation), so an on-path attacker can downgrade
// the result from "secure" to "insecure", but cannot forge a "secure" result.
package dnssec

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Status is the outcome of a DNSSEC chain validation.
type Status string

const (
	// StatusSecure means the full DNSSEC chain of trust, from the trust
	// anchors down to the host's address records, validated successfully.
	StatusSecure Status = "secure"
	// StatusInsecure means the domain (or one of its ancestors) is not
	// DNSSEC-signed, so DNSSEC offers no protection for this host.
	StatusInsecure Status = "insecure"
	// StatusBogus means the domain claims DNSSEC support but validation
	// failed: DNS answers for this host may have been tampered with.
	StatusBogus Status = "bogus"
	// StatusIndeterminate means the check could not be completed, for example
	// because no resolver is available or a query failed.
	StatusIndeterminate Status = "indeterminate"
)

// severity orders statuses so that combining results keeps the worst one.
var severity = map[Status]int{
	StatusSecure:        0,
	StatusIndeterminate: 1,
	StatusInsecure:      2,
	StatusBogus:         3,
}

// Result is the outcome of a DNSSEC check for a host.
type Result struct {
	Status Status
	// Detail is a technical explanation intended for logging, not for users.
	Detail string
}

// Verifier checks the DNSSEC chain of trust for a host name.
type Verifier interface {
	Verify(host string) Result
}

// Root zone trust anchors published by IANA,
// see https://data.iana.org/root-anchors/root-anchors.xml.
var rootTrustAnchors = []*dns.DS{
	// KSK-2017
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
	},
	// KSK-2024
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     38696,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
	},
}

const (
	defaultTimeout = 5 * time.Second
	maxChainDepth  = 8
	maxQueries     = 32
)

// ChainVerifier is a Verifier that validates the DNSSEC chain of trust by
// querying a recursive resolver and verifying all signatures locally.
// The zero value uses the system resolvers and the IANA root trust anchors.
type ChainVerifier struct {
	// Servers are the recursive resolvers to query, as "ip:port" addresses.
	// If empty, the system resolvers from /etc/resolv.conf are used; when
	// those are unavailable too, Verify returns StatusIndeterminate.
	Servers []string
	// TrustAnchors are the DS records the chain is anchored to. If empty, the
	// IANA root zone trust anchors are used.
	TrustAnchors []*dns.DS
	// Timeout applies per DNS query. Defaults to 5 seconds.
	Timeout time.Duration
}

var _ Verifier = (*ChainVerifier)(nil)

// Verify checks the DNSSEC chain of trust for the address records of host.
func (v *ChainVerifier) Verify(host string) Result {
	if net.ParseIP(host) != nil {
		return Result{StatusIndeterminate, "host is an IP address, no DNS lookup to validate"}
	}

	servers := v.Servers
	if len(servers) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			return Result{StatusIndeterminate, "no DNS resolver available"}
		}
		for _, server := range conf.Servers {
			servers = append(servers, net.JoinHostPort(server, conf.Port))
		}
	}

	anchors := v.TrustAnchors
	if len(anchors) == 0 {
		anchors = rootTrustAnchors
	}

	timeout := v.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	sess := &validationSession{
		servers:  servers,
		anchors:  anchors,
		timeout:  timeout,
		now:      time.Now(),
		zoneKeys: map[string]zoneKeysResult{},
	}
	return sess.verifyHost(dns.Fqdn(strings.ToLower(host)))
}

// validationSession holds the per-Verify state, including a cache of already
// validated zone keys so shared parts of the chain are validated once.
type validationSession struct {
	servers  []string
	anchors  []*dns.DS
	timeout  time.Duration
	now      time.Time
	zoneKeys map[string]zoneKeysResult
	depth    int
	queries  int
}

type zoneKeysResult struct {
	keys   []*dns.DNSKEY
	result Result
}

// verifyHost validates the address records the HTTPS connection to the host
// relies on. IPv4 is tried first, IPv6 when no A records exist.
func (s *validationSession) verifyHost(fqdn string) Result {
	var lastErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := s.query(fqdn, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		rrsets, sigs := groupRecords(resp.Answer)
		if len(rrsets) == 0 {
			continue
		}
		return s.verifyAnswer(rrsets, sigs)
	}
	if lastErr != nil {
		return Result{StatusIndeterminate, fmt.Sprintf("DNS query failed: %v", lastErr)}
	}
	return Result{StatusIndeterminate, "no address records found"}
}

// verifyAnswer validates every RRset in an answer section (the CNAME chain
// plus the final address records) and combines the results, keeping the worst.
func (s *validationSession) verifyAnswer(rrsets map[recordKey][]dns.RR, sigs map[recordKey][]*dns.RRSIG) Result {
	combined := Result{StatusSecure, "full chain of trust validated"}
	for key, rrset := range rrsets {
		res := s.verifyRRset(rrset, sigs[key])
		if severity[res.Status] > severity[combined.Status] {
			combined = res
		}
	}
	return combined
}

// verifyRRset validates a single RRset against its covering signatures.
func (s *validationSession) verifyRRset(rrset []dns.RR, sigs []*dns.RRSIG) Result {
	owner := strings.ToLower(rrset[0].Header().Name)
	if len(sigs) == 0 {
		return s.classifyUnsigned(owner)
	}

	// A single valid signature suffices; report the first failure otherwise.
	var firstFailure Result
	for i, sig := range sigs {
		res := s.verifySig(sig, rrset, owner)
		switch res.Status {
		case StatusSecure, StatusInsecure, StatusIndeterminate:
			return res
		}
		if i == 0 {
			firstFailure = res
		}
	}
	return firstFailure
}

// verifySig validates one RRSIG over an RRset, recursively establishing trust
// in the signer zone's keys.
func (s *validationSession) verifySig(sig *dns.RRSIG, rrset []dns.RR, owner string) Result {
	signer := strings.ToLower(sig.SignerName)
	if !dns.IsSubDomain(signer, owner) {
		return Result{StatusBogus, fmt.Sprintf("RRSIG signer %s is not an ancestor of %s", signer, owner)}
	}
	// DS records live in the parent zone; a DS RRset signed by the child zone
	// itself would let any zone forge its own chain of trust.
	if rrset[0].Header().Rrtype == dns.TypeDS && signer == owner {
		return Result{StatusBogus, fmt.Sprintf("DS RRset for %s is signed by the zone itself", owner)}
	}
	if !sig.ValidityPeriod(s.now) {
		return Result{StatusBogus, fmt.Sprintf("RRSIG for %s by %s is outside its validity period", owner, signer)}
	}

	keys, res := s.trustedZoneKeys(signer)
	if res.Status != StatusSecure {
		return res
	}
	for _, key := range keys {
		if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
			continue
		}
		if err := sig.Verify(key, rrset); err == nil {
			return Result{StatusSecure, ""}
		}
	}
	return Result{StatusBogus, fmt.Sprintf("no trusted DNSKEY of %s validates the RRSIG for %s", signer, owner)}
}

// trustedZoneKeys returns the validated DNSKEY set of a zone, establishing the
// chain of trust from the anchors down to the zone.
func (s *validationSession) trustedZoneKeys(zone string) ([]*dns.DNSKEY, Result) {
	if cached, ok := s.zoneKeys[zone]; ok {
		return cached.keys, cached.result
	}
	if s.depth >= maxChainDepth {
		return nil, Result{StatusIndeterminate, "maximum chain depth exceeded"}
	}
	s.depth++
	keys, result := s.resolveZoneKeys(zone)
	s.depth--
	s.zoneKeys[zone] = zoneKeysResult{keys, result}
	return keys, result
}

func (s *validationSession) resolveZoneKeys(zone string) ([]*dns.DNSKEY, Result) {
	// Establish the trusted DS set for this zone first: the trust anchors for
	// the anchor point, the validated DS RRset from the parent otherwise. Only
	// a zone with a secure delegation is expected to serve DNSKEY records.
	dsSet := s.anchors
	if zone != strings.ToLower(dns.Fqdn(s.anchors[0].Hdr.Name)) {
		dsResp, err := s.query(zone, dns.TypeDS)
		if err != nil {
			return nil, Result{StatusIndeterminate, fmt.Sprintf("DS query for %s failed: %v", zone, err)}
		}
		dsRRsets, dsSigs := groupRecords(dsResp.Answer)
		dsKey := recordKey{zone, dns.TypeDS}
		dsRRset := dsRRsets[dsKey]
		if len(dsRRset) == 0 {
			// Unsigned delegation: the chain of trust ends above this zone.
			return nil, Result{StatusInsecure, fmt.Sprintf("no DS records for %s, domain is not DNSSEC-protected", zone)}
		}
		if res := s.verifyRRset(dsRRset, dsSigs[dsKey]); res.Status != StatusSecure {
			return nil, res
		}
		dsSet = nil
		for _, rr := range dsRRset {
			if ds, ok := rr.(*dns.DS); ok {
				dsSet = append(dsSet, ds)
			}
		}
	}

	resp, err := s.query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, Result{StatusIndeterminate, fmt.Sprintf("DNSKEY query for %s failed: %v", zone, err)}
	}
	rrsets, sigs := groupRecords(resp.Answer)
	dnskeyKey := recordKey{zone, dns.TypeDNSKEY}
	var keys []*dns.DNSKEY
	for _, rr := range rrsets[dnskeyKey] {
		if key, ok := rr.(*dns.DNSKEY); ok && key.Flags&dns.ZONE != 0 {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, Result{StatusBogus, fmt.Sprintf("zone %s has a secure delegation but no DNSKEY records", zone)}
	}

	// A zone whose DS records only use algorithms we cannot validate must be
	// treated as unsigned, not as bogus.
	if !anySupported(dsSet) {
		return nil, Result{StatusInsecure, fmt.Sprintf("zone %s uses no supported DNSSEC algorithm", zone)}
	}

	// Find a key-signing key that matches a trusted DS record and verify it
	// signed the zone's DNSKEY RRset.
	dnskeyRRset := rrsets[dnskeyKey]
	for _, ds := range dsSet {
		for _, key := range keys {
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil || !strings.EqualFold(computed.Digest, ds.Digest) {
				continue
			}
			for _, sig := range sigs[dnskeyKey] {
				if sig.KeyTag != key.KeyTag() || sig.Algorithm != key.Algorithm || !sig.ValidityPeriod(s.now) {
					continue
				}
				if err := sig.Verify(key, dnskeyRRset); err == nil {
					return keys, Result{StatusSecure, ""}
				}
			}
		}
	}
	return nil, Result{StatusBogus, fmt.Sprintf("DNSKEY RRset of %s does not validate against its DS records", zone)}
}

// anySupported reports whether at least one DS record uses a signing algorithm
// and digest type this validator can verify.
func anySupported(dsSet []*dns.DS) bool {
	supportedAlgorithms := map[uint8]bool{
		dns.RSASHA256:       true,
		dns.RSASHA512:       true,
		dns.ECDSAP256SHA256: true,
		dns.ECDSAP384SHA384: true,
		dns.ED25519:         true,
	}
	supportedDigests := map[uint8]bool{
		dns.SHA1:   true,
		dns.SHA256: true,
		dns.SHA384: true,
	}
	for _, ds := range dsSet {
		if supportedAlgorithms[ds.Algorithm] && supportedDigests[ds.DigestType] {
			return true
		}
	}
	return false
}

// classifyUnsigned decides whether an unsigned answer is expected (unsigned
// zone: insecure) or a sign of tampering (signed zone: bogus).
func (s *validationSession) classifyUnsigned(owner string) Result {
	resp, err := s.query(owner, dns.TypeSOA)
	if err != nil {
		return Result{StatusIndeterminate, fmt.Sprintf("SOA query for %s failed: %v", owner, err)}
	}
	apex := ""
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				apex = strings.ToLower(soa.Header().Name)
				break
			}
		}
		if apex != "" {
			break
		}
	}
	if apex == "" {
		return Result{StatusIndeterminate, fmt.Sprintf("cannot determine the zone containing %s", owner)}
	}

	_, res := s.trustedZoneKeys(apex)
	if res.Status == StatusSecure {
		return Result{StatusBogus, fmt.Sprintf("zone %s is DNSSEC-signed but the answer for %s carries no signature", apex, owner)}
	}
	return res
}

// query sends a DNS query with the DO and CD bits set, falling back to TCP on
// truncation and trying each configured server until one answers.
func (s *validationSession) query(name string, qtype uint16) (*dns.Msg, error) {
	if s.queries >= maxQueries {
		return nil, fmt.Errorf("maximum number of DNS queries exceeded")
	}
	s.queries++

	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true
	// Checking Disabled: we validate signatures ourselves and want the data
	// even when the resolver considers it bogus.
	msg.CheckingDisabled = true
	msg.SetEdns0(4096, true)

	client := &dns.Client{Timeout: s.timeout}
	var lastErr error
	for _, server := range s.servers {
		resp, _, err := client.Exchange(msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			tcpClient := &dns.Client{Net: "tcp", Timeout: s.timeout}
			resp, _, err = tcpClient.Exchange(msg, server)
			if err != nil {
				lastErr = err
				continue
			}
		}
		if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		lastErr = fmt.Errorf("server %s returned rcode %s", server, dns.RcodeToString[resp.Rcode])
	}
	return nil, lastErr
}

// recordKey identifies an RRset within a message section.
type recordKey struct {
	name  string
	rtype uint16
}

// groupRecords splits a message section into RRsets and their covering RRSIGs.
func groupRecords(rrs []dns.RR) (map[recordKey][]dns.RR, map[recordKey][]*dns.RRSIG) {
	rrsets := map[recordKey][]dns.RR{}
	sigs := map[recordKey][]*dns.RRSIG{}
	for _, rr := range rrs {
		name := strings.ToLower(rr.Header().Name)
		if sig, ok := rr.(*dns.RRSIG); ok {
			key := recordKey{name, sig.TypeCovered}
			sigs[key] = append(sigs[key], sig)
			continue
		}
		key := recordKey{name, rr.Header().Rrtype}
		rrsets[key] = append(rrsets[key], rr)
	}
	return rrsets, sigs
}
