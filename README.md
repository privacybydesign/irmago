# irmago

`irmago` is an IRMA implementation in Go. It contains multiple libraries and applications:

* The Go package `irma` contains generic IRMA functionality such as parsing [credential and issuer definitions and public keys](https://github.com/privacybydesign/irma-demo-schememanager), parsing [IRMA metadata attributes](https://credentials.github.io/docs/irma.html#the-metadata-attribute), and structs representing messages of the [IRMA protocol](https://credentials.github.io/protocols/irma-protocol/).
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. It also implements the [keyshare protocol](https://github.com/privacybydesign/irma_keyshare_server) and handles registering to keyshare servers.
* The tool `schememgr` manages signatures on IRMA [scheme managers](https://credentials.github.io/docs/irma.html#scheme-managers): it can generate public-private keypairs for signing their directory structures, as well as creating and verifying these signatures.

For example, the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmago`.

## Running the unit tests

For running the unit tests, you need to run [irma_keyshare_server](https://github.com/credentials/irma_keyshare_server) and [irma_api_server](https://github.com/credentials/irma_api_server) locally.

### IRMA Keyshare Server

- Copy or symlink the `irma_configuration` folder from `testdata/` to the configuration of the Keyshare server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.
- Add the keyshare user used in the unit tests to the keyshare database by a command like this:

        mysql -uirma -pirma irma_keyshare < keyshareuser.sql

- Make sure `check_user_enabled` is set to false in the Keyshare server configuration. Other options are already setup correctly in the example configuration.


### IRMA API Server
- Copy or symlink the `irma_configuration` folder from `testdata/` to the configuration of the IRMA api server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.


### Running the tests
The tests can be run by using:

    go test

<!-- vim: set ts=4 sw=4: -->
