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

func GetSessionResult(token string) *irmaserver.SessionResult {
	session := sessions.get(token)
	if session != nil {
		return nil
	}
	return session.result
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
		status, output = responseJson(nil, getError(irmaserver.ErrorInvalidRequest, ""))
		return
	}

	// Fetch the session
	token := matches[1]
	verb := matches[2]
	session := sessions.get(token)
	if session == nil {
		conf.Logger.Warnf("Session not found: %s", token)
		status, output = responseJson(nil, getError(irmaserver.ErrorSessionUnknown, ""))
		return
	}
	session.Lock()
	defer session.Unlock()

	// However we return, if the session has been finished or cancelled by any of the handlers
	// then we should inform the user by returning a SessionResult - but only if we have not
	// already done this in the past, e.g. by a previous HTTP call handled by this function
	defer func() {
		if session.finished() && !session.returned {
			session.returned = true
			result = session.result
		}
	}()

	// Route to handler
	switch len(verb) {
	case 0:
		if method == "DELETE" {
			session.handleDelete()
			status = http.StatusOK
			return
		}
		if method == "GET" {
			h := http.Header(headers)
			min := &irma.ProtocolVersion{}
			max := &irma.ProtocolVersion{}
			if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
				status, output = responseJson(nil, session.fail(irmaserver.ErrorMalformedInput, err.Error()))
				return
			}
			if err := json.Unmarshal([]byte(h.Get(irma.MaxVersionHeader)), max); err != nil {
				status, output = responseJson(nil, session.fail(irmaserver.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = responseJson(session.handleGetRequest(min, max))
			return
		}
		status, output = responseJson(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
		return
	default:
		if method != "POST" {
			status, output = responseJson(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
			return
		}

		if verb == "commitments" && session.action == irma.ActionIssuing {
			commitments := &gabi.IssueCommitmentMessage{}
			if err := irma.UnmarshalValidate(message, commitments); err != nil {
				status, output = responseJson(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = responseJson(session.handlePostCommitments(commitments))
			return
		}
		if verb == "proofs" && session.action == irma.ActionDisclosing {
			proofs := gabi.ProofList{}
			if err := irma.UnmarshalValidate(message, &proofs); err != nil {
				status, output = responseJson(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = responseJson(session.handlePostProofs(proofs))
			return
		}
		if verb == "proofs" && session.action == irma.ActionSigning {
			signature := &irma.SignedMessage{}
			if err := irma.UnmarshalValidate(message, signature); err != nil {
				status, output = responseJson(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = responseJson(session.handlePostSignature(signature))
			return
		}

		status, output = responseJson(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
		return
	}
}
