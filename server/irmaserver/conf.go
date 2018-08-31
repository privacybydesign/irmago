package irmaserver

import (
	"crypto/rsa"
	"io/ioutil"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
)

type Configuration struct {
	*server.Configuration

	Port int

	// Whether or not incoming session requests should be authenticated. If false, anyone
	// can submit session requests. If true, the request is first authenticated against the
	// server configuration before the server accepts it.
	AuthenticateRequestors bool
	Requestors             map[string]Requestor // Requestor-specific permission and authentication configuration
	GlobalPermissions      Permissions          // Disclosing, signing or issuance permissions that apply to all requestors

	JwtIssuer  string // Used in the "iss" field of result JWTs from /result-jwt and /getproof
	PrivateKey string // Private key to sign result JWTs with. If absent, /result-jwt and /getproof are disabled.

	privateKey *rsa.PrivateKey
}

// Permissions specify which attributes or credential a requestor may verify or issue.
type Permissions struct {
	Disclosing []string
	Signing    []string
	Issuing    []string
}

// Requestor contains all configuration (disclosure or verification permissions and authentication)
// for a requestor.
type Requestor struct {
	Permissions

	AuthenticationMethod AuthenticationMethod
	AuthenticationKey    string
}

// CanIssue returns whether or not the specified requestor may issue the specified credentials.
// (In case of combined issuance/disclosure sessions, this method does not check whether or not
// the identity provider is allowed to verify the attributes being verified; use CanVerifyOrSign
// for that).
func (conf *Configuration) CanIssue(requestor string, creds []*irma.CredentialRequest) (bool, string) {
	permissions := append(conf.Requestors[requestor].Issuing, conf.GlobalPermissions.Issuing...)
	if len(permissions) == 0 { // requestor is not present in the permissions
		return false, ""
	}

	for _, cred := range creds {
		id := cred.CredentialTypeID
		if contains(permissions, "*") ||
			contains(permissions, id.Root()+".*") ||
			contains(permissions, id.IssuerIdentifier().String()+".*") ||
			contains(permissions, id.String()) {
			continue
		} else {
			return false, id.String()
		}
	}

	return true, ""
}

// CanVerifyOrSign returns whether or not the specified requestor may use the selected attributes
// in any of the supported session types.
func (conf *Configuration) CanVerifyOrSign(requestor string, action irma.Action, disjunctions irma.AttributeDisjunctionList) (bool, string) {
	var permissions []string
	switch action {
	case irma.ActionDisclosing:
		permissions = append(conf.Requestors[requestor].Disclosing, conf.GlobalPermissions.Disclosing...)
	case irma.ActionIssuing:
		permissions = append(conf.Requestors[requestor].Disclosing, conf.GlobalPermissions.Disclosing...)
	case irma.ActionSigning:
		permissions = append(conf.Requestors[requestor].Signing, conf.GlobalPermissions.Signing...)
	}
	if len(permissions) == 0 { // requestor is not present in the permissions
		return false, ""
	}

	for _, disjunction := range disjunctions {
		for _, attr := range disjunction.Attributes {
			if contains(permissions, "*") ||
				contains(permissions, attr.Root()+".*") ||
				contains(permissions, attr.CredentialTypeIdentifier().IssuerIdentifier().String()+".*") ||
				contains(permissions, attr.CredentialTypeIdentifier().String()+".*") ||
				contains(permissions, attr.String()) {
				continue
			} else {
				return false, attr.String()
			}
		}
	}

	return true, ""
}

func (conf *Configuration) initialize() error {
	if err := conf.readPrivateKey(); err != nil {
		return err
	}

	if !conf.AuthenticateRequestors {
		conf.Logger.Warn("Authentication of incoming session requests disabled")
		authenticators = map[AuthenticationMethod]Authenticator{AuthenticationMethodNone: NilAuthenticator{}}

		// Leaving the global permission whitelists empty in this mode means enabling it for everyone
		if len(conf.GlobalPermissions.Disclosing) == 0 {
			conf.Logger.Info("No disclosing whitelist found: allowing verification of any attribute")
			conf.GlobalPermissions.Disclosing = []string{"*"}
		}
		if len(conf.GlobalPermissions.Signing) == 0 {
			conf.Logger.Info("No signing whitelist found: allowing attribute-based signature sessions with any attribute")
			conf.GlobalPermissions.Signing = []string{"*"}
		}
		if len(conf.GlobalPermissions.Issuing) == 0 {
			conf.Logger.Info("No issuance whitelist found: allowing issuance of any credential (for which private keys are installed)")
			conf.GlobalPermissions.Issuing = []string{"*"}
		}
		return nil
	}

	authenticators = map[AuthenticationMethod]Authenticator{
		AuthenticationMethodPublicKey: &PublicKeyAuthenticator{publickeys: map[string]*rsa.PublicKey{}},
		AuthenticationMethodPSK:       &PresharedKeyAuthenticator{presharedkeys: map[string]string{}},
	}

	// Initialize authenticators
	for name, requestor := range conf.Requestors {
		authenticator, ok := authenticators[requestor.AuthenticationMethod]
		if !ok {
			return errors.Errorf("Requestor %s has unsupported authentication type")
		}
		if err := authenticator.Initialize(name, requestor); err != nil {
			return err
		}
	}

	return nil
}

func (conf *Configuration) readPrivateKey() error {
	if conf.PrivateKey == "" {
		return nil
	}

	var keybytes []byte
	var err error
	if strings.HasPrefix(conf.PrivateKey, "-----BEGIN") {
		keybytes = []byte(conf.PrivateKey)
	} else {
		if err = fs.AssertPathExists(conf.PrivateKey); err != nil {
			return err
		}
		if keybytes, err = ioutil.ReadFile(conf.PrivateKey); err != nil {
			return err
		}
	}

	conf.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keybytes)
	return err
}

// Return true iff query equals an element of strings.
func contains(strings []string, query string) bool {
	for _, s := range strings {
		if s == query {
			return true
		}
	}
	return false
}
