package backend

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

func Initialize(configuration *irmaserver.Configuration) error {
	conf = configuration

	if conf.Logger == nil {
		conf.Logger = logrus.New()
		conf.Logger.Level = logrus.DebugLevel
		conf.Logger.Formatter = &logrus.TextFormatter{}
	}

	if conf.IrmaConfiguration == nil {
		var err error
		conf.IrmaConfiguration, err = irma.NewConfiguration(conf.IrmaConfigurationPath, "")
		if err != nil {
			return err
		}
		if err = conf.IrmaConfiguration.ParseFolder(); err != nil {
			return err
		}
	}

	return nil
}

func StartSession(request irma.SessionRequest) (*irma.Qr, string, error) {
	if err := request.Validate(); err != nil {
		return nil, "", err
	}
	action := irma.ActionUnknown
	switch request.(type) {
	case *irma.DisclosureRequest:
		action = irma.ActionDisclosing
	case *irma.SignatureRequest:
		action = irma.ActionSigning
	case *irma.IssuanceRequest:
		action = irma.ActionIssuing
		if err := validateIssuanceRequest(request.(*irma.IssuanceRequest)); err != nil {
			return nil, "", err
		}
	default:
		conf.Logger.Warnf("Attempt to start session of invalid type")
		return nil, "", errors.New("Invalid session type")
	}

	session := newSession(action, request)
	conf.Logger.Infof("%s session started, token %s", action, session.token)
	return &irma.Qr{
		Type: action,
		URL:  session.token,
	}, session.token, nil
}

func HandleProtocolMessage(
	path string,
	method string,
	headers map[string][]string,
	message []byte,
) (status int, output []byte, result *irmaserver.SessionResult) {
	// Parse path into session and action
	if len(path) > 0 { // Remove any starting and trailing slash
		if path[0] == '/' {
			path = path[1:]
		}
		if path[len(path)-1] == '/' {
			path = path[:len(path)-1]
		}
	}
	conf.Logger.Debugf("Routing protocol message: %s %s", method, path)
	pattern := regexp.MustCompile("(\\w+)/?(\\w*)")
	matches := pattern.FindStringSubmatch(path)
	if len(matches) != 3 {
		conf.Logger.Warnf("Invalid URL: %s", path)
		return failSession(nil, irmaserver.ErrorInvalidRequest, "")
	}

	// Fetch the session
	token := matches[1]
	verb := matches[2]
	session := sessions.get(token)
	if session == nil {
		conf.Logger.Warnf("Session not found: %s", token)
		return failSession(nil, irmaserver.ErrorSessionUnknown, "")
	}

	// Route to handler
	switch len(verb) {
	case 0:
		if method == "DELETE" {
			return handleDelete(session)
		}
		if method == "GET" {
			h := http.Header(headers)
			min := &irma.ProtocolVersion{}
			max := &irma.ProtocolVersion{}
			if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
				return failSession(session, irmaserver.ErrorMalformedInput, err.Error())
			}
			if err := json.Unmarshal([]byte(h.Get(irma.MaxVersionHeader)), max); err != nil {
				return failSession(session, irmaserver.ErrorMalformedInput, err.Error())
			}
			return handleGetSession(session, min, max)
		}
		return failSession(session, irmaserver.ErrorInvalidRequest, "")
	default:
		if method == "POST" {
			if verb == "commitments" && session.action == irma.ActionIssuing {
				commitments := &gabi.IssueCommitmentMessage{}
				if err := irma.UnmarshalValidate(message, commitments); err != nil {
					return failSession(session, irmaserver.ErrorMalformedInput, "")
				}
				return handlePostCommitments(session, commitments)
			}
			if verb == "proofs" && session.action == irma.ActionDisclosing {
				proofs := gabi.ProofList{}
				if err := irma.UnmarshalValidate(message, &proofs); err != nil {
					return failSession(session, irmaserver.ErrorMalformedInput, "")
				}
				return handlePostProofs(session, proofs)
			}
			if verb == "proofs" && session.action == irma.ActionSigning {
				signature := &irma.SignedMessage{}
				if err := irma.UnmarshalValidate(message, signature); err != nil {
					return failSession(session, irmaserver.ErrorMalformedInput, "")
				}
				return handlePostSignature(session, signature)
			}
		}
		if method == "GET" && verb == "status" {
			return handleGetStatus(session)
		}
		return failSession(session, irmaserver.ErrorInvalidRequest, "")
	}
}
