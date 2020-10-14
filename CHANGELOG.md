# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2020-10-14
### Added
* Support for session binding to prevent shoulder surfing (i.e. make it impossible for someone in close physical proximity to a user to scan the QR code that was meant for the user)
  * Introduced new frontend endpoints to manage session binding
  * Introduced `irmaclient` protocol version 2.7 including the necessary protocol changes
  * The API of the `requestorserver` package has two new functions `SetFrontendOptions` and `BindingCompleted`
  * A new server status `"BINDING"` is introduced
* A new function `SessionStatus` is available in the API of the `requestorserver` to get a channel with status updates of an IRMA session

### Changes
* The `irma.SessionPackage` struct now contains an extra field `FrontendAuth`
* The `StartSession` function from the API of the `requestorserver` package now returns three values: the session pointer (type *irma.QR), the requestor token (type irma.RequestorToken) and the frontend authorization token (type irma.FrontendAuthorization)
* The `token` parameter, as used by most functions in the API of the `requestorserver` package, now has the type `irma.RequestorToken`
* The `server.Status` type has been moved to `irma.ServerStatus`; the related constants are also moved, e.g. from `server.StatusInitialized` to `irma.ServerStatusInitialized`

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

[0.6.0]: https://github.com/privacybydesign/irmago/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.5...v0.5.0
[0.5.0-rc.5]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.4...v0.5.0-rc.5
[0.5.0-rc.4]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.3...v0.5.0-rc.4
[0.5.0-rc.3]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.2...v0.5.0-rc.3
[0.5.0-rc.2]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.1...v0.5.0-rc.2
[0.5.0-rc.1]: https://github.com/privacybydesign/irmago/compare/v0.4.1...v0.5.0-rc.1
[0.4.1]: https://github.com/privacybydesign/irmago/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/privacybydesign/irmago/tree/v0.4.0
