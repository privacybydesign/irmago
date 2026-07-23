package common

import "net/http"

// HTTPClient is the shared HTTP client used across irmago for ad-hoc outbound
// requests (EUDI configuration, OpenID4VCI/OpenID4VP, SD-JWT VC type-metadata
// fetching and remote image downloads). Centralizing it gives a single place
// to configure outbound client behaviour instead of scattering per-call
// http.Client values with diverging settings.
//
// It uses http.DefaultTransport (the shared default connection pool) and sets
// no client-level Timeout on purpose: a Client.Timeout keeps running while the
// response body is read and interrupts it (see issue #606). Callers bound
// their requests with a per-request context deadline instead.
//
// The dedicated clients in irma/transport.go (retryable, cookie-jar and
// SIGPIPE-aware transport) and internal/test are intentionally not replaced by
// this one: they carry purpose-specific configuration rather than being ad-hoc
// default clients.
var HTTPClient = &http.Client{}
