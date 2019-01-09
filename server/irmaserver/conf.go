package irmaserver

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
)

type Configuration struct {
	*server.Configuration `mapstructure:",squash"`

	// Whether or not incoming session requests should be authenticated. If false, anyone
	// can submit session requests. If true, the request is first authenticated against the
	// server configuration before the server accepts it.
	DisableRequestorAuthentication bool `json:"noauth" mapstructure:"noauth"`

	// Address to listen at
	ListenAddress string `json:"listenaddr" mapstructure:"listenaddr"`
	// Port to listen at
	Port int `json:"port" mapstructure:"port"`
	// TLS configuration
	TlsCertificate     string `json:"tlscertificate" mapstructure:"tlscertificate"`
	TlsCertificateFile string `json:"tlscertificatefile" mapstructure:"tlscertificatefile"`
	TlsPrivateKey      string `json:"tlsprivatekey" mapstructure:"tlsprivatekey"`
	TlsPrivateKeyFile  string `json:"tlsprivatekeyfile" mapstructure:"tlsprivatekeyfile"`

	// If specified, start a separate server for the IRMA app at his port
	ClientPort int `json:"clientport" mapstructure:"clientport"`
	// If clientport is specified, the server for the IRMA app listens at this address
	ClientListenAddress string `json:"clientlistenaddr" mapstructure:"clientlistenaddr"`
	// TLS configuration for irmaclient HTTP API
	ClientTlsCertificate     string `json:"clienttlscertificate" mapstructure:"clienttlscertificate"`
	ClientTlsCertificateFile string `json:"clienttlscertificatefile" mapstructure:"clienttlscertificatefile"`
	ClientTlsPrivateKey      string `json:"clienttlsprivatekey" mapstructure:"clienttlsprivatekey"`
	ClientTlsPrivateKeyFile  string `json:"clienttlsprivatekeyfile" mapstructure:"clienttlsprivatekeyfile"`

	// Requestor-specific permission and authentication configuration
	RequestorsString string               `json:"-" mapstructure:"requestors"`
	Requestors       map[string]Requestor `json:"requestors"`

	// Disclosing, signing or issuance permissions that apply to all requestors
	GlobalPermissionsString string      `json:"-" mapstructure:"permissions"`
	GlobalPermissions       Permissions `json:"permissions" mapstructure:"permissions"`

	// Used in the "iss" field of result JWTs from /result-jwt and /getproof
	JwtIssuer string `json:"jwtissuer" mapstructure:"jwtissuer"`

	// Private key to sign result JWTs with. If absent, /result-jwt and /getproof are disabled.
	JwtPrivateKey     string `json:"jwtprivatekey" mapstructure:"jwtprivatekey"`
	JwtPrivateKeyFile string `json:"jwtprivatekeyfile" mapstructure:"jwtprivatekeyfile"`

	// Max age in seconds of a session request JWT (using iat field)
	MaxRequestAge int `json:"maxrequestage" mapstructure:"maxrequestage"`

	Verbose int  `json:"verbose" mapstructure:"verbose"`
	Quiet   bool `json:"quiet" mapstructure:"quiet"`

	jwtPrivateKey *rsa.PrivateKey
}

// Permissions specify which attributes or credential a requestor may verify or issue.
type Permissions struct {
	Disclosing []string `json:"disclose" mapstructure:"disclose"`
	Signing    []string `json:"sign" mapstructure:"sign"`
	Issuing    []string `json:"issue" mapstructure:"issue"`
}

// Requestor contains all configuration (disclosure or verification permissions and authentication)
// for a requestor.
type Requestor struct {
	Permissions `mapstructure:",squash"`

	AuthenticationMethod  AuthenticationMethod `json:"authmethod" mapstructure:"authmethod"`
	AuthenticationKey     string               `json:"key" mapstructure:"key"`
	AuthenticationKeyFile string               `json:"keyfile" mapstructure:"keyfile"`
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

	if conf.DisableRequestorAuthentication {
		conf.Logger.Warn("Authentication of incoming session requests disabled: anyone who can reach this server can use it")
		authenticators = map[AuthenticationMethod]Authenticator{AuthenticationMethodNone: NilAuthenticator{}}
	} else {
		authenticators = map[AuthenticationMethod]Authenticator{
			AuthenticationMethodHmac:      &HmacAuthenticator{hmackeys: map[string]interface{}{}},
			AuthenticationMethodPublicKey: &PublicKeyAuthenticator{publickeys: map[string]interface{}{}},
			AuthenticationMethodToken:     &PresharedKeyAuthenticator{presharedkeys: map[string]string{}},
		}

		// Initialize authenticators
		for name, requestor := range conf.Requestors {
			authenticator, ok := authenticators[requestor.AuthenticationMethod]
			if !ok {
				return errors.Errorf("Requestor %s has unsupported authentication type", name)
			}
			if err := authenticator.Initialize(name, requestor); err != nil {
				return err
			}
		}
	}

	if conf.Port <= 0 || conf.Port > 65535 {
		return errors.Errorf("Port must be between 1 and 65535 (was %d)", conf.Port)
	}

	if conf.ClientPort != 0 && conf.ClientPort == conf.Port {
		return errors.New("If clientport is given it must be different from port")
	}
	if conf.ClientPort < 0 || conf.ClientPort > 65535 {
		return errors.Errorf("clientport must be between 0 and 65535 (was %d)", conf.ClientPort)
	}
	if conf.ClientListenAddress != "" && conf.ClientPort == 0 {
		return errors.New("clientlistenaddr must be combined with a nonzero clientport")
	}

	tlsConf, err := conf.tlsConfig()
	if err != nil {
		return errors.WrapPrefix(err, "Failed to read TLS configuration", 0)
	}
	clientTlsConf, err := conf.clientTlsConfig()
	if err != nil {
		return errors.WrapPrefix(err, "Failed to read client TLS configuration", 0)
	}

	if err := conf.validatePermissions(); err != nil {
		return err
	}

	if conf.URL != "" {
		if !strings.HasSuffix(conf.URL, "/") {
			conf.URL = conf.URL + "/"
		}
		conf.URL = conf.URL + "irma/"
		// replace "port" in url with actual port
		port := conf.ClientPort
		if port == 0 {
			port = conf.Port
		}
		replace := "$1:" + strconv.Itoa(port)
		conf.URL = string(regexp.MustCompile("(https?://[^/]*):port").ReplaceAll([]byte(conf.URL), []byte(replace)))
		separateClientServer := conf.separateClientServer()
		if (separateClientServer && clientTlsConf != nil) || (!separateClientServer && tlsConf != nil) {
			if strings.HasPrefix(conf.URL, "http://") {
				conf.URL = "https://" + conf.URL[len("http://"):]
			}
		}
	}

	return nil
}

func (conf *Configuration) validatePermissions() error {
	if conf.DisableRequestorAuthentication && len(conf.Requestors) != 0 {
		return errors.New("Requestors must not be configured when requestor authentication is disabled")
	}

	errs := conf.validatePermissionSet("Global", conf.GlobalPermissions)
	for name, requestor := range conf.Requestors {
		errs = append(errs, conf.validatePermissionSet("Requestor "+name, requestor.Permissions)...)
	}
	if len(errs) != 0 {
		return errors.New("Errors encountered in permissions:\n" + strings.Join(errs, "\n"))
	}
	return nil
}

func (conf *Configuration) validatePermissionSet(requestor string, requestorperms Permissions) []string {
	var errs []string
	perms := map[string][]string{
		"issuing":    requestorperms.Issuing,
		"signing":    requestorperms.Signing,
		"disclosing": requestorperms.Disclosing,
	}
	permissionlength := map[string]int{"issuing": 3, "signing": 4, "disclosing": 4}

	for typ, typeperms := range perms {
		for _, permission := range typeperms {
			parts := strings.Split(permission, ".")
			if parts[len(parts)-1] == "*" {
				if len(parts) > permissionlength[typ] {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s' should have at most %d parts", requestor, typ, permission, permissionlength[typ]))
				}
			} else {
				if len(parts) != permissionlength[typ] {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s' should have %d parts", requestor, typ, permission, permissionlength[typ]))
				}
			}
			if len(parts) > 0 && parts[0] != "*" {
				if conf.IrmaConfiguration.SchemeManagers[irma.NewSchemeManagerIdentifier(parts[0])] == nil {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s': unknown scheme", requestor, typ, permission))
					continue // no sense in checking if issuer, credtype or attr type are known; they won't be
				}
			}
			if len(parts) > 1 && parts[1] != "*" {
				id := irma.NewIssuerIdentifier(strings.Join(parts[:2], "."))
				if conf.IrmaConfiguration.Issuers[id] == nil {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s': unknown issuer", requestor, typ, permission))
					continue
				}
			}
			if len(parts) > 2 && parts[2] != "*" {
				id := irma.NewCredentialTypeIdentifier(strings.Join(parts[:3], "."))
				if conf.IrmaConfiguration.CredentialTypes[id] == nil {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s': unknown credential type", requestor, typ, permission))
					continue
				}
			}
			if len(parts) > 3 && parts[3] != "*" {
				id := irma.NewAttributeTypeIdentifier(strings.Join(parts[:4], "."))
				if conf.IrmaConfiguration.AttributeTypes[id] == nil {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s': unknown attribute type", requestor, typ, permission))
					continue
				}
			}
		}
	}

	return errs
}

func (conf *Configuration) clientTlsConfig() (*tls.Config, error) {
	return conf.readTlsConf(conf.ClientTlsCertificate, conf.ClientTlsCertificateFile, conf.ClientTlsPrivateKey, conf.ClientTlsPrivateKeyFile)
}

func (conf *Configuration) tlsConfig() (*tls.Config, error) {
	return conf.readTlsConf(conf.TlsCertificate, conf.TlsCertificateFile, conf.TlsPrivateKey, conf.TlsPrivateKeyFile)
}

func (conf *Configuration) readTlsConf(cert, certfile, key, keyfile string) (*tls.Config, error) {
	if cert == "" && certfile == "" && key == "" && keyfile == "" {
		return nil, nil
	}

	var certbts, keybts []byte
	var err error
	if certbts, err = fs.ReadKey(cert, certfile); err != nil {
		return nil, err
	}
	if keybts, err = fs.ReadKey(key, keyfile); err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair(certbts, keybts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{cer},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}, nil
}

func (conf *Configuration) readPrivateKey() error {
	if conf.JwtPrivateKey == "" && conf.JwtPrivateKeyFile == "" {
		return nil
	}

	keybytes, err := fs.ReadKey(conf.JwtPrivateKey, conf.JwtPrivateKeyFile)
	if err != nil {
		return errors.WrapPrefix(err, "failed to read private key", 0)
	}

	conf.jwtPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keybytes)
	return err
}

func (conf *Configuration) separateClientServer() bool {
	return conf.ClientPort != 0
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
