# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.5.0-rc.1]: https://github.com/privacybydesign/irmago/compare/v0.4.1...v0.5.0-rc.1
[0.4.1]: https://github.com/privacybydesign/irmago/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/privacybydesign/irmago/tree/v0.4.0
