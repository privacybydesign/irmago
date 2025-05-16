client.Candidates() -> [][]DisclosureCandidates

session.requestPermission() uses that to create a list of candidates and call Handler.Request<type>Permission(candidates)

What i need to do is add some more details to the DisclosureCandidates and make it more generic

sessionHandler {
    sessionId (get from flutter)
    dismisser (get from NewSession())
    pinrequestor ()
}
instance passed to NewSession(), then also stored in map[id]sessionHandler


Handler contains KeysharePinRequestor and parts of KeyhareHandler

session implements the keyshareSessionHandler and puts itself as the handler for newKeyshareSession

// ------------------

client.Candidates() -> [][][]*DisclosureCandidate

DisclosureCandidate {
	*irma.AttributeIdentifier
	Value        irma.TranslatedString
	Expired      bool
	Revoked      bool
	NotRevokable bool
}

old Handler.RequestVerificationPermission took in these candidates along with the original condiscon
Based on these candidates the flutter side would know which ones are available, but not the full details of each one aren't known at this point.
Instead they're read from the full configuration

Condiscon: Conjunction of disjunction of conjunction
and, or, and

An empty list for an "or"/disjunction means that the rule is optional

Does this map onto DCQL?

// -----------------------------------

The app side must know:
- What attributes are requested
- What credentials they belong to
- Which ones are not on the device yet
- What the values are of the ones that are present on the device
- Whether a credential:
    - Has been added/issued during this disclosure session
    - Whether a credential is revoked

Problem: In SD-JWT world a lot of metadata is missing and should be fetched from an endpoint on the issuer
The endpoint is (probably https://issuer.eudiw.dev/.well-known/openid-credential-issuer)

Problem: When doing a disclosure session and issuing some missing credentials during this session,
how do we update the state of the disclosure session to show these newly issued credentials as present?
Right now I think it's done via configuration updates

Could create an API to fetch the IrmaConfiguration -> little benefit over current situation, not scalable in the future
Could send updates for RequestVerificationPermission() -> would need a more complicated session system in irmaclient
