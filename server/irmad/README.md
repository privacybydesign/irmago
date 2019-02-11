# irma server

`irma server` is an IRMA server executable (daemon) allowing you to perform IRMA sessions with
[IRMA apps](https://github.com/privacybydesign/irma_mobile).
It exposes the following:
 * HTTP endpoints used by the IRMA app during IRMA sessions
 * a JSON API for [requestors](https://credentials.github.io/docs/irma.html#participants),
   allowing them to request the server to verify or issue attributes.



## Installing
If necessary, clone `irmago` and install dependencies with [dep](https://github.com/golang/dep):
```
mkdir -p $GOPATH/github.com/privacybydesign && cd $GOPATH/github.com/privacybydesign
git clone https://github.com/privacybydesign/irmago && cd irmago
dep ensure
```

Build and install:
```
cd irma
go install
```

Run `irma server -h` to see configuration options or just `irma server` to run the server with the default configuration.
In order to verify your configuration, run `irma server check -v`.


## Starting a session
Assuming the server runs in the default configuration (see below; in particular [requestor authentication](#requestor-authentication) is disabled (`no_auth` is `true`) and the `irma-demo` scheme is installed), issue `irma-demo.MijnOverheid.ageLower` attributes using the [`session`](../../irma) subcommand of the `irma` tool:
```
irma session --server http://localhost:8088 --issue irma-demo.MijnOverheid.ageLower=yes,yes,yes,no
```
Verify the `irma-demo.MijnOverheid.ageLower.over18` attribute:
```
$ irma session --server http://localhost:8088 --disclose irma-demo.MijnOverheid.ageLower.over18
```
These print QRs in your terminal that you can scan with your IRMA app to perform the session.



## Configuring
Run `irma server -h` to see all configuration options.
Each option may be passed as:
 1. a command line flags (e.g. `--listen-addr`)
 2. a environmental variable (e.g. `IRMASERVER_LISTEN_ADDR`)
 3. an item in a configuration file (e.g. `"listen_addr"`) (which may be in JSON, TOML or YAML)
 
 with the following rules:
 * Flags supersede environmental variables which supersede configuration file entries.
 * Dashes are used in flags, but underscores are used in environmental variables and configuration file entries.
 * Environmental variables are uppercased and prefixed with `IRMASERVER_`.
 * The `requestors` option is special: when passed as a flag or environmental variable, it must be passed in JSON.

In order to see the configuration that the server uses after having gathered input from these sources, specify `-v` or `-vv` or use the `verbose` option. Use `irma server check -v` (with the same flags, env vars and config files as `irma server`) to check your configuration for correctness before running the server.

#### Configuration files
A configuration file can be provided using the `config` option (for example: `irma server --config ./irmaserver.json`). When not specified, the server looks for a configuration file called `irmaserver.json` or `irmaserver.toml` or `irmaserver.yaml` in (1) the current path; (2) `/etc/irmaserver/`; (3) `$HOME/irmaserver`, in that order. A configuration file is not required; if none is found at any of these locations the server takes its configuration from just command line flags and environmental variables.

#### Default configuration
In the default configuration (run `irma server check -v` to see it) the server is immediately usable. In particular, it
* uses the default [IRMA schemes](https://credentials.github.io/docs/irma.html#scheme-managers) ([pbdf](https://github.com/credentials/pbdf-schememanager) and [irma-demo](https://github.com/credentials/irma-demo-schememanager)), downloading them if necessary
* allows anyone to use the server [without authentication](#requestor-authentication) (the `no_auth` setting is `true`).

If the server is reachable from the internet, you should consider enabling authentication of session requests.

#### Keys and certificate
For each configuration option that refers to some kind of key or certificate (for example `jwt_privkey`), there is a corresponding option with the `_file` suffix (for example `jwt_privkey_file`). Keys can be specified either by setting former to a (PEM) string, or setting the the latter to a file containing the (PEM) string.

#### Production mode
When running the server in production, enable the `production` option. This enables stricter defaults on the configuration options for safety and prints warnings on possibly unsafe configurations.

#### HTTP server endpoints
The HTTP endpoints that this server offers is split into two parts:
* `/session`: used by the requestor to start sessions, check session status, or get session results.
* `/irma`: used by the IRMA app during IRMA sessions.

In the default mode, the server starts one HTTP server that offers both, configured with `listen_addr` and `port`. If however the `client_port` and `client_listen_addr` options are provided, then the server starts two separate HTTP servers:
* `/session` attaches to the address and port provided with `port` and `listen_addr`.
* `/irma` attaches to the address and port provided with `client_port` and `client_listen_addr`.

The `/irma` endpoints must always be reachable for the IRMA app. Using this double server mode you can restrict access to the `/session` endpoints by e.g. setting `listen_addr` to `127.0.0.1` or to an interface only reachable from an internal network. Restricting access to the `/session` endpoints in this way may make requestor authentication unnecessary.

#### Requestor authentication
The server runs in one of two modes: it either accepts all session requests from anyone that can reach the server, or it accepts only authenticated session requests from authorized requestors. This can be toggled with the `no_auth` boolean option. The default is `true` (requests are not authenticated) when `production` is not enabled, and `false` otherwise.

The server supports three authentication methods:
 * POSTing the JSON session request with an API token in the `Authorization` HTTP header
 * POSTing the session request in a [JWT](https://jwt.io/) asymmetrically signed with RSA (RS256)
 * POSTing the session request in a [JWT](https://jwt.io/) symmetrically signed with HS256

Authorized requestors can be configured with the `requestor` option. For example, the following configuration file snippet configures a requestor called `myapp` using the API token authentication method.
```json
{
    "requestors": {
        "myapp": {
            "auth_method": "token",
            "key": "eGE2PSomOT84amVVdTU"
        }
    }
} 
```

#### Permissions
For each of the three IRMA session types (attribute verification; attribute issuance; and attribute-based signature sessions), permission to use specific attributes/credentials can be granted in the configuration.

#### Signed JWT session results

#### TLS

#### Email

Users of the server are encouraged to provide an email address with the `email` option, subscribing for notifications about changes in the IRMA software or ecosystem. [More information](../#specifying-an-email-address). In `production` mode, it is required to either provide an email address or to explicitly out with the `no_email` option. 

## See also

This executable wraps the Go library [`requestorserver`](../requestorserver) which wraps the Go library [`irmaserver`](../irmaserver).

The [client](../../irmaclient) corresponding to this server is implemented by the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile).

This server replaces the Java [irma_api_server](https://github.com/privacybydesign/irma_api_server). 
