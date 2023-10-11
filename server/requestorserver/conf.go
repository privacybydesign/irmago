package requestorserver

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
)

type Configuration struct {
	*server.Configuration `mapstructure:",squash"`

	// Disclosing, signing or issuance permissions that apply to all requestors
	Permissions          `mapstructure:",squash"`
	SkipPrivateKeysCheck bool `json:"skip_private_keys_check" mapstructure:"skip_private_keys_check"`

	// Whether or not incoming session requests should be authenticated. If false, anyone
	// can submit session requests. If true, the request is first authenticated against the
	// server configuration before the server accepts it.
	DisableRequestorAuthentication bool `json:"no_auth" mapstructure:"no_auth"`

	// Address to listen at
	ListenAddress string `json:"listen_addr" mapstructure:"listen_addr"`
	// Port to listen at
	Port int `json:"port" mapstructure:"port"`
	// Route requests via this path, so instead of POST /session, it will
	// be POST {ApiPrefix}/session.  Should start with a "/".
	ApiPrefix string `json:"api_prefix" mapstructure:"api_prefix"`
	// TLS configuration
	TlsCertificate     string `json:"tls_cert" mapstructure:"tls_cert"`
	TlsCertificateFile string `json:"tls_cert_file" mapstructure:"tls_cert_file"`
	TlsPrivateKey      string `json:"tls_privkey" mapstructure:"tls_privkey"`
	TlsPrivateKeyFile  string `json:"tls_privkey_file" mapstructure:"tls_privkey_file"`

	// If specified, start a separate server for the IRMA app at his port
	ClientPort int `json:"client_port" mapstructure:"client_port"`
	// If clientport is specified, the server for the IRMA app listens at this address
	ClientListenAddress string `json:"client_listen_addr" mapstructure:"client_listen_addr"`
	// TLS configuration for irmaclient HTTP API
	ClientTlsCertificate     string `json:"client_tls_cert" mapstructure:"client_tls_cert"`
	ClientTlsCertificateFile string `json:"client_tls_cert_file" mapstructure:"client_tls_cert_file"`
	ClientTlsPrivateKey      string `json:"client_tls_privkey" mapstructure:"client_tls_privkey"`
	ClientTlsPrivateKeyFile  string `json:"client_tls_privkey_file" mapstructure:"client_tls_privkey_file"`

	// Requestor-specific permission and authentication configuration
	Requestors map[string]Requestor `json:"requestors"`

	// Max age in seconds of a session request JWT (using iat field)
	MaxRequestAge int `json:"max_request_age" mapstructure:"max_request_age"`

	// Host files under this path as static files (leave empty to disable)
	StaticPath string `json:"static_path" mapstructure:"static_path"`
	// Host static files under this URL prefix
	StaticPrefix string `json:"static_prefix" mapstructure:"static_prefix"`
}

// Permissions specify which attributes or credential a requestor may verify or issue.
type Permissions struct {
	Disclosing []string `json:"disclose_perms" mapstructure:"disclose_perms"`
	Signing    []string `json:"sign_perms" mapstructure:"sign_perms"`
	Issuing    []string `json:"issue_perms" mapstructure:"issue_perms"`
	Revoking   []string `json:"revoke_perms" mapstructure:"revoke_perms"`

	Hosts []string `json:"host_perms" mapstructure:"host_perms"`
}

// Requestor contains all configuration (disclosure or verification permissions and authentication)
// for a requestor.
type Requestor struct {
	Permissions `mapstructure:",squash"`

	AuthenticationMethod  AuthenticationMethod `json:"auth_method" mapstructure:"auth_method"`
	AuthenticationKey     string               `json:"key" mapstructure:"key"`
	AuthenticationKeyFile string               `json:"key_file" mapstructure:"key_file"`
}

func (conf *Configuration) CanRequest(requestor string, request irma.SessionRequest) (bool, string) {
	if request.Action() == irma.ActionIssuing {
		if ok, reason := conf.CanIssue(requestor, request.(*irma.IssuanceRequest).Credentials); !ok {
			return false, reason
		}
	}

	condiscon := request.Disclosure().Disclose
	if len(condiscon) > 0 {
		if ok, reason := conf.CanVerifyOrSign(requestor, request.Action(), condiscon); !ok {
			return false, reason
		}
	}

	defaultURL, err := url.Parse(conf.URL)
	if err != nil {
		return false, "default host is invalid"
	}

	// If no host is specified in the request, then the default URL from the configuration will be used.
	// We should take this into account when checking the permissions.
	host := request.Base().Host
	if host == "" {
		host = defaultURL.Host
	}

	// If no host is specified in the requestor configuration, then we only allow the default host.
	if len(conf.Requestors[requestor].Hosts) == 0 && host == defaultURL.Host {
		return true, ""
	}

	// For all host patterns being set in the requestor configuration, check whether the requested host matches it.
	for _, hostPattern := range conf.Requestors[requestor].Hosts {
		if match, _ := path.Match(hostPattern, host); match {
			return true, ""
		}
	}
	return false, "requestor not allowed to use the requested host"
}

// CanIssue returns whether or not the specified requestor may issue the specified credentials.
// (In case of combined issuance/disclosure sessions, this method does not check whether or not
// the identity provider is allowed to verify the attributes being verified; use CanVerifyOrSign
// for that).
func (conf *Configuration) CanIssue(requestor string, creds []*irma.CredentialRequest) (bool, string) {
	permissions := append(conf.Requestors[requestor].Issuing, conf.Issuing...)
	if len(permissions) == 0 { // requestor is not present in the permissions
		return false, ""
	}

	for _, cred := range creds {
		id := cred.CredentialTypeID
		if slices.Contains(permissions, "*") ||
			slices.Contains(permissions, id.Root()+".*") ||
			slices.Contains(permissions, id.IssuerIdentifier().String()+".*") ||
			slices.Contains(permissions, id.String()) {
			continue
		} else {
			return false, id.String()
		}
	}

	return true, ""
}

// CanVerifyOrSign returns whether or not the specified requestor may use the selected attributes
// in any of the supported session types.
func (conf *Configuration) CanVerifyOrSign(requestor string, action irma.Action, disjunctions irma.AttributeConDisCon) (bool, string) {
	var permissions []string
	switch action {
	case irma.ActionDisclosing:
		permissions = append(conf.Requestors[requestor].Disclosing, conf.Disclosing...)
	case irma.ActionIssuing:
		permissions = append(conf.Requestors[requestor].Disclosing, conf.Disclosing...)
	case irma.ActionSigning:
		permissions = append(conf.Requestors[requestor].Signing, conf.Signing...)
	}
	if len(permissions) == 0 { // requestor is not present in the permissions
		return false, ""
	}

	err := disjunctions.Iterate(func(attr *irma.AttributeRequest) error {
		if slices.Contains(permissions, "*") ||
			slices.Contains(permissions, attr.Type.Root()+".*") ||
			slices.Contains(permissions, attr.Type.CredentialTypeIdentifier().IssuerIdentifier().String()+".*") ||
			slices.Contains(permissions, attr.Type.CredentialTypeIdentifier().String()+".*") ||
			slices.Contains(permissions, attr.Type.String()) {
			return nil
		} else {
			return errors.New(attr.Type.String())
		}
	})
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

func (conf *Configuration) CanRevoke(requestor string, cred irma.CredentialTypeIdentifier) (bool, string) {
	permissions := append(conf.Requestors[requestor].Revoking, conf.Revoking...)
	if len(permissions) == 0 { // requestor is not present in the permissions
		return false, ""
	}
	_, err := conf.IrmaConfiguration.Revocation.Keys.PrivateKeyLatest(cred.IssuerIdentifier())
	if err != nil {
		return false, err.Error()
	}
	if slices.Contains(permissions, "*") ||
		slices.Contains(permissions, cred.Root()+".*") ||
		slices.Contains(permissions, cred.IssuerIdentifier().String()+".*") ||
		slices.Contains(permissions, cred.String()) {
		return true, ""
	}
	return false, cred.String()
}

func (conf *Configuration) initialize() error {
	if conf.DisableRequestorAuthentication {
		authenticators = map[AuthenticationMethod]Authenticator{AuthenticationMethodNone: NilAuthenticator{}}
		conf.Logger.Warn("Authentication of incoming session requests disabled: anyone who can reach this server can use it")
		havekeys := conf.HavePrivateKeys()
		if len(conf.Permissions.Issuing) > 0 && havekeys {
			if conf.separateClientServer() || !conf.Production {
				conf.Logger.Warn("Issuance enabled and private keys installed: anyone who can reach this server can use it to issue attributes")
			} else {
				return errors.New("If issuing is enabled in production mode, requestor authentication must be enabled, or client_listen_addr and client_port must be used")
			}
		}
	} else {
		if len(conf.Requestors) == 0 {
			revServer := false
			for _, s := range conf.RevocationSettings {
				if s.Server {
					revServer = true
				}
			}
			if !revServer {
				return errors.New("No requestors configured; either configure one or more requestors or disable requestor authentication")
			}
		}
		authenticators = map[AuthenticationMethod]Authenticator{
			AuthenticationMethodHmac:      &HmacAuthenticator{hmackeys: map[string]interface{}{}, maxRequestAge: conf.MaxRequestAge},
			AuthenticationMethodPublicKey: &PublicKeyAuthenticator{publickeys: map[string]interface{}{}, maxRequestAge: conf.MaxRequestAge},
			AuthenticationMethodToken:     &PresharedKeyAuthenticator{presharedkeys: map[string]string{}},
		}

		// Initialize authenticators
		for name, requestor := range conf.Requestors {
			authenticator, ok := authenticators[requestor.AuthenticationMethod]
			if !ok {
				return errors.Errorf("Requestor %s has unsupported authentication type %s (supported methods: %s, %s, %s)",
					name, requestor.AuthenticationMethod, AuthenticationMethodToken, AuthenticationMethodHmac, AuthenticationMethodPublicKey)
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
		return errors.New("If client_port is given it must be different from port")
	}
	if conf.ClientPort < 0 || conf.ClientPort > 65535 {
		return errors.Errorf("client_port must be between 0 and 65535 (was %d)", conf.ClientPort)
	}
	if conf.ClientListenAddress != "" && conf.ClientPort == 0 {
		return errors.New("client_listen_addr must be combined with a nonzero client_port")
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

	if conf.StaticPath != "" {
		if err := common.AssertPathExists(conf.StaticPath); err != nil {
			return errors.WrapPrefix(err, "Invalid static_path", 0)
		}
		if conf.StaticPrefix[0] != '/' {
			return errors.New("static_prefix must start with a slash, was " + conf.StaticPrefix)
		}
		if len(conf.StaticPrefix) > 1 && !strings.HasSuffix(conf.StaticPrefix, "/") {
			conf.StaticPrefix = conf.StaticPrefix + "/"
		}
	}

	if conf.URL != "" {
		if !strings.HasSuffix(conf.URL, "/") {
			conf.URL = conf.URL + "/"
		}
		if !strings.HasSuffix(conf.URL, "irma/") {
			conf.URL = conf.URL + "irma/"
		}
		// replace "port" in url with actual port
		port := conf.ClientPort
		if port == 0 {
			port = conf.Port
		}
		conf.URL = server.ReplacePortString(conf.URL, port)

		separateClientServer := conf.separateClientServer()
		if (separateClientServer && clientTlsConf != nil) || (!separateClientServer && tlsConf != nil) {
			if strings.HasPrefix(conf.URL, "http://") {
				conf.URL = "https://" + conf.URL[len("http://"):]
			}
		}
	}

	if !strings.HasSuffix(conf.ApiPrefix, "/") {
		conf.ApiPrefix += "/"
	}

	if !strings.HasPrefix(conf.ApiPrefix, "/") {
		return errors.Errorf("api_prefix must start with a slash, but doesn't: %s", conf.ApiPrefix)
	}

	if conf.URL != "" && !strings.HasSuffix(conf.URL, conf.ApiPrefix+"irma/") {
		conf.Logger.Warnf("Are the URL and API-prefix set correctly?: %s does not end with %s.", conf.URL, conf.ApiPrefix+"irma/")
	}

	if len(conf.StaticSessions) != 0 && conf.JwtRSAPrivateKey == nil {
		conf.Logger.Warn("Static sessions enabled and no JWT private key installed. Ensure that POSTs to the callback URLs of static sessions are trustworthy by keeping the callback URLs secret and by using HTTPS.")
	}

	return nil
}

func (conf *Configuration) validatePermissions() error {
	if conf.DisableRequestorAuthentication && len(conf.Requestors) != 0 {
		return errors.New("Requestors must not be configured when requestor authentication is disabled")
	}

	errs := conf.validatePermissionSet("Global", conf.Permissions)
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
		"revoking":   requestorperms.Revoking,
	}
	permissionlength := map[string]int{"issuing": 3, "signing": 4, "disclosing": 4, "revoking": 3}

	for typ, typeperms := range perms {
		for _, permission := range typeperms {
			switch strings.Count(permission, "*") {
			case 0: // ok, nop
			case 1:
				if permission[len(permission)-1] != '*' {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s' contains asterisk not at end of line", requestor, typ, permission))
				}
			default:
				errs = append(errs, fmt.Sprintf("%s %s permission '%s' contains too many asterisks (at most 1 permitted)", requestor, typ, permission))
			}
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
				credtype := conf.IrmaConfiguration.CredentialTypes[id]
				if credtype == nil {
					errs = append(errs, fmt.Sprintf("%s %s permission '%s': unknown credential type", requestor, typ, permission))
					continue
				}
				if (typ == "issuing" || typ == "revoking") && !conf.SkipPrivateKeysCheck {
					sk, err := conf.IrmaConfiguration.PrivateKeys.Latest(credtype.IssuerIdentifier())
					if err != nil {
						errs = append(errs, fmt.Sprintf("%s %s permission '%s': failed to load private key: %s", requestor, typ, permission, err))
						continue
					}
					if sk == nil {
						errs = append(errs, fmt.Sprintf("%s %s permission '%s': private key not installed", requestor, typ, permission))
						continue
					}
					if typ == "revoking" {
						if ok := sk.RevocationSupported(); !ok {
							errs = append(errs, fmt.Sprintf("%s %s permission '%s': private key does not support revocation (add revocation key material to it using \"irma issuer revocation keypair\")", requestor, typ, permission))
							continue
						}
					}
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
	return server.TLSConf(conf.ClientTlsCertificate, conf.ClientTlsCertificateFile, conf.ClientTlsPrivateKey, conf.ClientTlsPrivateKeyFile)
}

func (conf *Configuration) tlsConfig() (*tls.Config, error) {
	return server.TLSConf(conf.TlsCertificate, conf.TlsCertificateFile, conf.TlsPrivateKey, conf.TlsPrivateKeyFile)
}

func (conf *Configuration) separateClientServer() bool {
	return conf.ClientPort != 0
}
