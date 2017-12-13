irmago
======

**DO NOT USE!** This library is in heavy development and is in constant flux. It is not ready for use.

Irmago is an IRMA client in Go: it can receive IRMA attributes, store them, disclose them to others, and use them to create attribute-based signatures. In more detail:

 * It is the client (like the [IRMA Android app](https://github.com/credentials/irma_android_cardemu)) in the [IRMA protocol](https://credentials.github.io/protocols/irma-protocol/)
 * It parses [credential and issuer definitions and public keys](https://github.com/credentials/irma_configuration)
 * It also implements the [keyshare protocol](https://github.com/credentials/irma_keyshare_server) and handles registering to keyshare servers.


## Running the unit tests

For running the unit tests, you need to run [irma_keyshare_server](https://github.com/credentials/irma_keyshare_server) and [irma_api_server](https://github.com/credentials/irma_api_server) locally.

### IRMA Keyshare Server

- Copy the `irma_configuration` folder from `testdata/` to the configuration of the Keyshare server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.
- Add the keyshare user used in the unit tests to the keyshare database by a command like this:

        mysql -uirma -pirma irma_keyshare < keyshareuser.sql

- Make sure `check_user_enabled` is set to false in the Keyshare server configuration. Other options are already setup correctly in the example configuration.


### IRMA Api Server
- Copy the `irma_configuration` folder from `testdata/` to the configuration of the IRMA api server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.


## Running the tests
The tests can be run by using:

    go test

<!-- vim: set ts=4 sw=4: -->
