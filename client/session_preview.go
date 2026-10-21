package client

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/common"
	irma "github.com/privacybydesign/irmago/irma"
)

// SessionPreviewKind is what a session will be, as far as its pointer says.
type SessionPreviewKind string

const (
	SessionPreviewKind_Disclosure SessionPreviewKind = "disclosure"
	SessionPreviewKind_Issuance   SessionPreviewKind = "issuance"
	SessionPreviewKind_Signature  SessionPreviewKind = "signature"
	// The pointer does not say (an IRMA redirect pointer).
	SessionPreviewKind_Unknown SessionPreviewKind = "unknown"
)

// SessionPreviewKnowledge is how much the preview knows about who asks.
type SessionPreviewKnowledge string

const (
	// A requestor in the requestor scheme: its name and logo, verified as the
	// session itself will be.
	SessionPreviewKnowledge_Registered SessionPreviewKnowledge = "registered"
	// An IRMA requestor not in the scheme: its host is all there is, also
	// during the session.
	SessionPreviewKnowledge_Unregistered SessionPreviewKnowledge = "unregistered"
	// OpenID4VP or OpenID4VCI: only the host the request comes from. Who that
	// is shows once the request (or the issuer's metadata) is fetched.
	SessionPreviewKnowledge_Host SessionPreviewKnowledge = "host"
	// Nothing: not even a host.
	SessionPreviewKnowledge_None SessionPreviewKnowledge = "none"
)

// SessionPreview is what the app can show about a session before it starts:
// worked out from the pointer and the local configuration only, without
// contacting any server. The app shows it on the lock screen while the
// session waits for the PIN.
type SessionPreview struct {
	Kind      SessionPreviewKind      `json:"kind"`
	Protocol  clientmodels.Protocol   `json:"protocol"`
	Knowledge SessionPreviewKnowledge `json:"knowledge"`
	// The host the request comes from; empty when not known.
	Host string `json:"host"`
	// The requestor, only when Knowledge is Registered or Unregistered.
	Requestor *clientmodels.TrustedParty `json:"requestor,omitempty"`
}

// PreviewSession tells what the session that sessionrequest (the same JSON
// as for NewSession) would start is, and who it is from, without starting
// it or contacting any server.
func (client *Client) PreviewSession(sessionrequest string) (*SessionPreview, error) {
	var req SessionRequestData
	if err := json.Unmarshal([]byte(sessionrequest), &req); err != nil {
		return nil, err
	}
	return previewSession(req, client.irmaClient.Configuration.Requestors, client.locale()), nil
}

func previewSession(req SessionRequestData, requestors map[string]*irma.RequestorInfo, locale string) *SessionPreview {
	preview := &SessionPreview{
		Kind:      previewKind(req.Type),
		Protocol:  req.Protocol,
		Knowledge: SessionPreviewKnowledge_None,
	}
	switch req.Protocol {
	case clientmodels.Protocol_OpenID4VP:
		preview.Kind = SessionPreviewKind_Disclosure
		preview.Host = openid4vpHost(req.URL)
	case clientmodels.Protocol_OpenID4VCI:
		preview.Kind = SessionPreviewKind_Issuance
		preview.Host = openid4vciHost(req.URL)
	default:
		if req.Type == irma.ActionRedirect {
			// The real session type comes from the server.
			return preview
		}
		previewIrma(preview, req.URL, requestors, locale)
		return preview
	}
	if preview.Host != "" {
		preview.Knowledge = SessionPreviewKnowledge_Host
	}
	return preview
}

func previewKind(action irma.Action) SessionPreviewKind {
	switch action {
	case irma.ActionDisclosing:
		return SessionPreviewKind_Disclosure
	case irma.ActionIssuing:
		return SessionPreviewKind_Issuance
	case irma.ActionSigning:
		return SessionPreviewKind_Signature
	}
	return SessionPreviewKind_Unknown
}

// previewIrma looks the session URL's host up in the requestor scheme, as
// the IRMA session does when it starts (irmaclient's requestorInfo).
func previewIrma(preview *SessionPreview, serverURL string, requestors map[string]*irma.RequestorInfo, locale string) {
	u, err := url.ParseRequestURI(serverURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := u.Hostname()
	preview.Host = host
	info, present := requestors[host]
	registered := present && (u.Scheme == "https" || !common.ForceHTTPS) &&
		(info.ValidUntil == nil || info.ValidUntil.After(irma.Timestamp(time.Now())))
	if !registered {
		info = irma.NewRequestorInfo(host)
	}
	party := requestorInfoToTrustedParty(info, locale)
	preview.Requestor = &party
	if registered && !info.Unverified {
		preview.Knowledge = SessionPreviewKnowledge_Registered
	} else {
		preview.Knowledge = SessionPreviewKnowledge_Unregistered
	}
}

// openid4vpHost is the host an OpenID4VP request names, from its client_id
// (x509_san_dns, redirect_uri, a did:web or a plain URL), else from its
// request_uri. It is not verified: it is shown as where the request comes
// from, not as who sent it.
func openid4vpHost(raw string) string {
	q := queryOf(raw)
	if q == nil {
		return ""
	}
	clientID := q.Get("client_id")
	for _, prefix := range []string{"x509_san_dns:", "dns:"} {
		if host, ok := strings.CutPrefix(clientID, prefix); ok && host != "" {
			return host
		}
	}
	if uri, ok := strings.CutPrefix(clientID, "redirect_uri:"); ok {
		if host := hostOf(uri); host != "" {
			return host
		}
	}
	if did, ok := strings.CutPrefix(clientID, "decentralized_identifier:"); ok {
		clientID = did
	}
	if web, ok := strings.CutPrefix(clientID, "did:web:"); ok {
		// did:web:example.com:path → example.com (a port is percent-encoded).
		host, _, _ := strings.Cut(web, ":")
		if decoded, err := url.PathUnescape(host); err == nil {
			host = decoded
		}
		if h := hostOf("https://" + host); h != "" {
			return h
		}
	}
	if host := hostOf(clientID); host != "" {
		return host
	}
	for _, key := range []string{"request_uri", "response_uri"} {
		if host := hostOf(q.Get(key)); host != "" {
			return host
		}
	}
	return ""
}

// openid4vciHost is the credential issuer's host, from an offer passed by
// value, else the host of the offer's URI.
func openid4vciHost(raw string) string {
	q := queryOf(raw)
	if q == nil {
		return ""
	}
	if offer := q.Get("credential_offer"); offer != "" {
		var parsed struct {
			CredentialIssuer string `json:"credential_issuer"`
		}
		if json.Unmarshal([]byte(offer), &parsed) == nil {
			if host := hostOf(parsed.CredentialIssuer); host != "" {
				return host
			}
		}
	}
	return hostOf(q.Get("credential_offer_uri"))
}

func queryOf(raw string) url.Values {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u.Query()
}

func hostOf(raw string) string {
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
