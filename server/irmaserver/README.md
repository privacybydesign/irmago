# irmaserver &nbsp; [![GoDoc](https://godoc.org/github.com/privacybydesign/irmago/server/irmaserver?status.svg)](https://godoc.org/github.com/privacybydesign/irmago/server/irmaserver)

`irmaserver` is a Go library providing a HTTP server that handles IRMA session with the IRMA app, and functions for starting and managing IRMA sessions.

```go
err := irmaserver.Initialize(&server.Configuration{
    URL: "https://example.com:1234", // Replace with address that IRMA apps can reach
}) // Check err
_ = http.ListenAndServe(":1234", irmaserver.HandlerFunc()) // Start the server

// In another goroutine, request a demo over18 attribute
request := `{
    "type": "disclosing",
    "content": [{ "label": "Over 18", "attributes": [ "irma-demo.MijnOverheid.ageLower.over18" ]}]
}`
qr, _, err := irmaserver.StartSession(request, func (r *server.SessionResult) {
    fmt.Println("Session done, result: ", server.ToJson(r))
})
// Check err

// Send qr to frontend and render as QR
```

## Installing

Clone `irmago` and install dependencies with [dep](https://github.com/golang/dep):
```
mkdir -p $GOPATH/github.com/privacybydesign && cd $GOPATH/github.com/privacybydesign
git clone https://github.com/privacybydesign/irmago && cd irmago
dep ensure
```

## Configuring
The server is configured by passing a `server.Configuration` instance to `irmaserver.New()`. For the options and their meaning, see [Godoc](https://godoc.org/github.com/privacybydesign/irmago/server/#Configuration).

## Email

Users are encouraged to provide an email address with the `Email` option in the `server.Configuration` struct, subscribing for notifications about changes in the IRMA software or ecosystem. [More information](../#specifying-an-email-address).

## See also

The  Go library [`requestorserver`](../requestorserver) wraps the functions that this library exposes
for starting and managing IRMA sessions into HTTP endpoints. The [`irmad`](../irmad) binary wraps
`requestorserver` into an executable
 

The [client](../../irmaclient) corresponding to this server is implemented by the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile).
