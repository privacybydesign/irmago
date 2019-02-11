# Package `server`

This package contains the following components of the IRMA server:

 * [`irmaserver`](irmaserver): Go library providing an HTTP server that handles IRMA session with the IRMA app, and functions for starting and managing IRMA sessions.
 * [`requestorserver`](requestorserver): Go library providing an HTTP server that combines the HTTP endpoints from `irmaserver` with endpoints to start and manage IRMA sessions.
 * [`irmad`](irmad): server executable (daemon) wrapping `requestorserver`, exposed as the `irma server` subcommand.

### Specifying an email address
In the configuration of each of the three components above, an email addres can be specified. If specified, the email address is uploaded to the [Privacy by Design Foundation](https://privacybydesign.foundation/) and subscribed to receive updates about changes in the IRMA software or ecosystem. If you use any of the above servers, especially in production environments, we encourage you to provide your email address.

If you provide an email address, you will be notified of changes such as major updates of the IRMA server, and breaking changes in any part of the IRMA infrastructure that would require you to update your IRMA server or otherwise take action in order to stay compatible with the rest of the IRMA ecosystem.

 * It will be very low volume (on average perhaps one email per several months). 
 * If you have provided your email address in the past and wish to be unsubscribed, please email [the Foundation](https://privacybydesign.foundation/contact-en/).
 * See also the Foundation's [privacy policy](https://privacybydesign.foundation/privacy-policy-en/).
