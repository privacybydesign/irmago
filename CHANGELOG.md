# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2021-07-27
This release contains several large new features. In particular, the shoulder surf prevention feature brings a number of breaking changes in the API, mainly within the `irmaserver` package.

### Added

* Support for [chained IRMA sessions](https://irma.app/docs/next/chained-sessions)
* A Go rewrite of the [keyshare server](https://irma.app/docs/overview/#irma-pin-codes-using-the-keyshare-server) (see the new `irma keyshare` commands), succeeding the [now deprecated `irma_keyshare_server`](https://github.com/credentials/irma_keyshare_server)
* Added a function `SessionStatus()` in the `irmaserver` package returning a channel with status updates of an IRMA session
* Added `--api-prefix` parameter to the IRMA server for prefixing its API endpoints with a string
* Added `--max-session-lifetime` parameter to the IRMA server for setting the session expiry (default 5 minutes)
* Shoulder surfing prevention: support for device pairing to prevent shoulder surfing (i.e. make it impossible for someone in close physical proximity to a user to scan the QR code that was meant for the user)
  * Introduced new endpoints used by the [frontend](https://github.com/privacybydesign/irma-frontend-packages) to manage device pairing
  * The API of the `irmaserver` package has two new functions `SetFrontendOptions` and `PairingCompleted`
  * A new server status `"PAIRING"` is introduced

### Changes

* During scheme parsing, folders found in the scheme folder not present in the assets (when configured) are removed
* Shoulder surfing prevention:
  * The `server.SessionPackage` struct now contains an extra field `FrontendAuth`
  * The `irma.Qr` struct now contains an optional field `PairingRecommended` (named `pairingHint` when being marshalled to JSON) that is set to true when pairing is recommended for that session, as indication to the frontend
  * The `StartSession` function from the API of the `irmaserver` package now returns three values: the session pointer (type `*irma.QR`), the requestor token (type `irma.RequestorToken`) and the frontend authorization token (type `irma.FrontendAuthorization`)
  * The `token` parameter, as used by most functions in the API of the `irmaserver` package, now has the type `irma.RequestorToken`
  * The `server.Status` type has been moved to `irma.ServerStatus`; the related constants are also moved, e.g. from `server.StatusInitialized` to `irma.ServerStatusInitialized`
  
### Fixed
* Bug causing IRMA server startup to fail when revocation is enabled
* Bug causing sessions to fail when revocation is enabled and the issuer has multiple revocation-enabled keys
* Incorrectly cased SQL column name used in revocation data lookup
* Bug causing issuance time in revocation records being floored to credential validity epoch boundaries

## [0.7.0] - 2021-03-17
### Fixed
* Bug causing scheme updating to fail if OS temp dir is on other file system than the schemes
* Prevent session result JWTs from being expired immediately if no expiry is specified is set in the session request; instead in that case they expire after two minutes
* When POSTing session result to the `callbackUrl` specified in session request, set `Content-Type` to `application/json` for JSON messages
* Fixed panic during scheme downloading on Windows
* Correctly decode randomblind attributes when verifying disclosures/signatures

### Added
* Add request URL to log entry when IRMA server encounters an error (404 or otherwise) during HTTP request handling
* Add flag `--allow-unsigned-callbacks` to IRMA server to allow `callbackUrl` in session requests when no JWT private key is installed
* Add flag `--augment-client-return-url` to IRMA server to enable augmenting client return URL with server session token as query parameter (needs to be additionally enabled in session requests)
* Add new `irma issuer keyprove` and `irma issuer keyverify` commands to generate and verify zero-knowledge proofs of correct generation of issuer private/public keypairs

### Changed
* Clarify warning and suppress stacktrace in IRMA server log entry in case `/statusevents` is hit while SSE is disabled
* Force Unix (LF) line endings in schemes during scheme signing for consistency
* Moved revocation commands from `irma issuer revocation` to just `irma issuer`

## [0.6.1] - 2020-12-15
### Changed
* Change endpoint to which [IRMA server admin email address](https://irma.app/docs/email/) is sent and include IRMA server version number

### Fixed
* Bug that could cause schemes on disk to enter an inconsistent state, causing IRMA server to refuse to startup
* Nil deref during IRMA server startup in case local IP address failed to be determined
* Bug causing requestor scheme updating to fail

## [0.6.0] - 2020-10-20
### Added
* Support for "randomblind" attributes (if enabled in the scheme), for e.g. election use cases: attributes containing large random numbers issued in such a way that 1) the issuer does not learn their value while still providing a valid signature over the credential containing the attributes, and 2) the attribute value will be unequal to all previously issued randomblind attributes with overwhelming probability. Once issued, these attributes can be disclosed normally (i.e., only the issuance protocol is different for these attributes).
* Initial support (currently limited to issuing sessions) in `irmaclient` for "pretty verifier names": human-readable and translatable requestor names to show in the IRMA app during a session to identify the requestor, instead of just a hostname, defined in a new scheme type called "requestor schemes" (e.g. https://github.com/privacybydesign/pbdf-requestors)

### Changed
* Renamed and refactored several (mostly internal) functions dealing with installing, parsing and updating schemes, to support both scheme types (normal schemes as well as requestor schemes)
* `irmaclient` now includes suggestions for non-singletons in the disclosure candidates during sessions, like it does for singletons not in the user's wallet

### Fixed
* Bug that would cause the IRMA server to log required values of attributes to be disclosed, when logging the session request
* Bug in `irmaclient` leading to the wrong error message in case of bad internet connection

## [0.5.1] - 2020-09-17
### Changed
* Switched to forks of `cobra`, `viper`, and `pflag` so that depending packages don't require `replace` directives in their go.mod

## [0.5.0] - 2020-09-03
### Fixed
* Bug in scheme update mechanism leading to `UNKNOWN_PUBLIC_KEY` errors when new public keys have been added to the scheme
* Several bugfixes in `irmaclient`

## [0.5.0-rc.5] - 2020-08-11
### Added
* Support disabling scheme auto-updating in `irma session`
* Support revocation in `irma session` and `irma request`

### Fixed
* Fixed bug in server configuration defaults when enabling production mode through config file
* Fixed bug that would kill server-sent events (SSE) connections after several seconds
* Fixed invalidation of local copy of index if local scheme is newer than the remote one
* Ignore absence of FAQ fields and category in credentialtypes during `irma scheme verify`

### Security
* Abort issuance or disclosure in server and client in case of expired public keys

## [0.5.0-rc.4] - 2020-06-18
### Added
* Support for parallel sessions (e.g. issuance of missing credentials during a disclosure session) to `irmaclient`

### Fixed
* Several minor bugs in `irmaclient`

### Security
* The IRMA server now keeps issuer private keys in memory as short as possible


## [0.5.0-rc.3] - 2020-05-14
### Added
* Various additions to `irmaclient` for the [new IRMA app](https://github.com/privacybydesign/irmamobile), among others:
  * Several new fields in `irma.CredentialType` for specifying e.g. help messages and card colors
  * Added developer mode enabling non-HTTPS connections to IRMA servers for local testing (see below)

### Fixed
* Problems with `--privkeys` option to IRMA server

### Security
* `irma` command, IRMA server and `irmaclient` will now enforce HTTPS for outgoing connections whenever possible
* Update supported TLS ciphers and curves for IRMA server
* Fixed potential bug allowing MitM attacker to arbitrarily change installed schemes
* Fixed potential DoS attack in IRMA server endpoints (sending it large amounts of data or keeping connections open indefinitely)


## [0.5.0-rc.2] - 2020-04-21

### Added
* Revocation of previously issued credentials (see [documentation](https://irma.app/docs/revocation/))
* Support HTTP/2 in IRMA server and app
* Option `--skip-permission-keys-check` to IRMA server disabling checking that all required private keys are present in the server configuration 

### Changed
* Use go modules instead of `dep` for tracking and locking dependencies

### Fixed
* `irmaserver` HTTP handler returns 404 an 405 as JSON error messages as expected
* Consistently use a docopt/git/aptitude like format for usage sections in help of `irma` subcommands
* Incorrect default value of `--url` flag to `irma session` subcommand
* IRMA server no longer allows nonsensical wildcard usage in [requestor permissions](https://irma.app/docs/irma-server/#permissions)

### Security
* `irma issuer keygen` now has default keylength 2048
* Added various sanity checks to files and file paths
* Fixed potential scheme downgrade attack when installing/updating schemes in MitM scenarios


## [0.5.0-rc.1] - 2020-03-03
### Added
- Include `clientReturnURL` in session request

### Changed
- All (translated) names of issuers and credential types of demo schemes (i.e. `irma-demo`) must now start with `Demo `
- `irmaclient` now uses bbolt for storage
- When the `irmaclient` receives a credential identical to another older one, the older one is overwritten
- Scheme signing and verification now supports symlinks

### Fixed
- Unclear error message when the request's `Content-Type` HTTP header is not properly set
- Unclear error message when non-optional attributes are missing in issuance request
- Scheme verification now ignores deprecated issuers and keys and ignores missing IssueURL tags in credential types
- `irma server` no longer crashes at startup if no network interfaces are available
- Various bugs in `irma server` configuration


## [0.4.1] - 2019-10-15
### Changed
- Renamed `irma session` flag `--authmethod` to `--auth-method` for consistency with server `Configuration` struct

### Fixed
- Fix bug that would prevent downloading of demo private keys of demo schemes on server startup and scheme updating
- `irma server` now respects the `disable_schemes_update` option like the `irmaserver` library (#63)
- Other small fixes


## [0.4.0] - 2019-10-09
### Added
- New irma server feature: static (e.g. printable) QRs that start preconfigured sessions, see [documentation](https://irma.app/docs/irma-server/#static-irma-qrs)
- irma server now returns attribute issuance time to the requestor after the session has finished

### Fixed
- Hopefully fix “unknown or expired session” errors that would sometimes occur in the IRMA app in bad network conditions
- Combined issuance-disclosure requests with two schemes one of which has a keyshare server now work as expected
- Various other bugfixes

[0.8.0]: https://github.com/privacybydesign/irmago/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/privacybydesign/irmago/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/privacybydesign/irmago/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/privacybydesign/irmago/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/privacybydesign/irmago/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.5...v0.5.0
[0.5.0-rc.5]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.4...v0.5.0-rc.5
[0.5.0-rc.4]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.3...v0.5.0-rc.4
[0.5.0-rc.3]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.2...v0.5.0-rc.3
[0.5.0-rc.2]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.1...v0.5.0-rc.2
[0.5.0-rc.1]: https://github.com/privacybydesign/irmago/compare/v0.4.1...v0.5.0-rc.1
[0.4.1]: https://github.com/privacybydesign/irmago/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/privacybydesign/irmago/tree/v0.4.0
