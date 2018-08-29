package irmaserver

import (
	"crypto/rsa"
	"io/ioutil"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
)

type Configuration struct {
	*server.Configuration

	Port int

	AuthenticateRequestors bool
	Requestors             map[string]Requestor
	GlobalPermissions      Permissions

	JwtIssuer  string
	PrivateKey string

	privateKey *rsa.PrivateKey
}

type Permissions struct {
	Disclosing []string
	Signing    []string
	Issuing    []string
}

type Requestor struct {
	Permissions

	AuthenticationMethod AuthenticationMethod
	AuthenticationKey    string
}

func contains(strings []string, query string) bool {
	for _, s := range strings {
		if s == query {
			return true
		}
	}
	return false
}

func (conf *Configuration) CanIssue(requestor string, creds []*irma.CredentialRequest) (bool, string) {
	permissions := append(conf.Requestors[requestor].Issuing, conf.GlobalPermissions.Issuing...)

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
		conf.Logger.Warn("Requestor authentication disabled")
		authenticators = map[string]Authenticator{AuthenticationMethodNone: NilAuthenticator{}}

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

	authenticators = map[string]Authenticator{
		AuthenticationMethodPublicKey: &PublicKeyAuthenticator{},
		AuthenticationMethodPSK:       &PresharedKeyAuthenticator{},
	}

	for _, authenticator := range authenticators {
		if err := authenticator.Initialize(conf.Requestors); err != nil {
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
