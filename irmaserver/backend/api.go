package backend

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/mhe/gabi/big"
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
	irmaserver.Logger = conf.Logger

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

	if conf.PrivateKeys == nil {
		conf.PrivateKeys = make(map[irma.IssuerIdentifier]*gabi.PrivateKey)
	}
	if conf.PrivateKeysPath != "" {
		files, err := ioutil.ReadDir(conf.PrivateKeysPath)
		if err != nil {
			return err
		}
		for _, file := range files {
			filename := file.Name()
			issid := irma.NewIssuerIdentifier(strings.TrimSuffix(filename, filepath.Ext(filename))) // strip .xml
			if _, ok := conf.IrmaConfiguration.Issuers[issid]; !ok {
				return errors.Errorf("Private key %s belongs to an unknown issuer", filename)
			}
			sk, err := gabi.NewPrivateKeyFromFile(filepath.Join(conf.PrivateKeysPath, filename))
			if err != nil {
				return err
			}
			conf.PrivateKeys[issid] = sk
		}
	}
	for issid, sk := range conf.PrivateKeys {
		pk, err := conf.IrmaConfiguration.PublicKey(issid, int(sk.Counter))
		if err != nil {
			return err
		}
		if pk == nil {
			return errors.Errorf("Missing public key belonging to private key %s-%d", issid.String(), sk.Counter)
		}
		if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
			return errors.Errorf("Private key %s-%d does not belong to corresponding public key", issid.String(), sk.Counter)
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
	if session == nil {
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
		status, output = irmaserver.JsonResponse(nil, irmaserver.RemoteError(irmaserver.ErrorInvalidRequest, ""))
		return
	}

	// Fetch the session
	token := matches[1]
	verb := matches[2]
	session := sessions.get(token)
	if session == nil {
		conf.Logger.Warnf("Session not found: %s", token)
		status, output = irmaserver.JsonResponse(nil, irmaserver.RemoteError(irmaserver.ErrorSessionUnknown, ""))
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
		sessions.update(token, session)
	}()

	// Route to handler
	switch len(verb) {
	case 0:
		if method == http.MethodDelete {
			session.handleDelete()
			status = http.StatusOK
			return
		}
		if method == http.MethodGet {
			h := http.Header(headers)
			min := &irma.ProtocolVersion{}
			max := &irma.ProtocolVersion{}
			if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
				status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorMalformedInput, err.Error()))
				return
			}
			if err := json.Unmarshal([]byte(h.Get(irma.MaxVersionHeader)), max); err != nil {
				status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = irmaserver.JsonResponse(session.handleGetRequest(min, max))
			return
		}
		status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
		return
	default:
		if method != http.MethodPost {
			status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
			return
		}

		if verb == "commitments" && session.action == irma.ActionIssuing {
			commitments := &gabi.IssueCommitmentMessage{}
			if err := irma.UnmarshalValidate(message, commitments); err != nil {
				status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = irmaserver.JsonResponse(session.handlePostCommitments(commitments))
			return
		}
		if verb == "proofs" && session.action == irma.ActionDisclosing {
			proofs := gabi.ProofList{}
			if err := irma.UnmarshalValidate(message, &proofs); err != nil {
				status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = irmaserver.JsonResponse(session.handlePostProofs(proofs))
			return
		}
		if verb == "proofs" && session.action == irma.ActionSigning {
			signature := &irma.SignedMessage{}
			if err := irma.UnmarshalValidate(message, signature); err != nil {
				status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorMalformedInput, ""))
				return
			}
			status, output = irmaserver.JsonResponse(session.handlePostSignature(signature))
			return
		}

		status, output = irmaserver.JsonResponse(nil, session.fail(irmaserver.ErrorInvalidRequest, ""))
		return
	}
}
