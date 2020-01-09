package irmaclient

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

const nonrevUpdateInterval = 10 // Once every 10 seconds

func (client *Client) startRevocation() {
	// For every credential supporting revocation, compute nonrevocation caches in async jobs
	for credid, attrsets := range client.attributes {
		for i, attrs := range attrsets {
			if attrs.CredentialType() == nil || !attrs.CredentialType().SupportsRevocation() {
				continue
			}
			credid := credid // make copy of same name to capture the value for closure below
			i := i           // see https://golang.org/doc/faq#closures_and_goroutines
			client.jobs <- func() {
				if err := client.nonrevCredPrepareCache(credid, i); err != nil {
					client.reportError(err)
				}
			}
		}
	}

	// Of each credential supporting revocation, we periodically update its nonrevocation witness
	// by fetching updates from the issuer's server, such that:
	// - The time interval between two updates is random so that the server cannot recognize us
	//   using the update interval,
	// - Updating happens regularly even if the app is rarely used.
	// We do this by every 10 seconds updating the credential with a low probability, which
	// increases over time since the last update.
	client.Configuration.Scheduler.Every(nonrevUpdateInterval).Seconds().Do(func() {
		for credid, attrsets := range client.attributes {
			for i, attrs := range attrsets {
				if !attrs.CredentialType().SupportsRevocation() {
					continue
				}
				cred, err := client.credential(credid, i)
				if err != nil {
					client.reportError(err)
					continue
				}
				if cred.NonRevocationWitness == nil {
					continue
				}
				r, err := randomfloat()
				if err != nil {
					client.reportError(err)
					break
				}
				if r < probability(cred.NonRevocationWitness.Updated) {
					irma.Logger.Debugf("scheduling nonrevocation witness remote update for %s-%d", credid, i)
					client.jobs <- func() {
						updated, err := cred.NonrevUpdateFromServer(client.Configuration)
						if err != nil {
							client.reportError(err)
							return
						}
						if updated {
							if err = client.nonrevCredPrepareCache(credid, i); err != nil {
								client.reportError(err)
								return
							}
						}
					}
				}
			}
		}
	})
}

// probability returns a float between 0 and asymptote, representing a probability
// that asymptotically increases to the asymptote, reaching
// a reference probability at a reference index.
func probability(lastUpdate time.Time) float64 {
	const (
		asymptote      = 1.0 / 3          // max probability
		refindex       = 7 * 60 * 60 * 24 // Week
		refprobability = 0.75 * asymptote // probability after one week
	)
	f := math.Tan(math.Pi * refprobability / (2 * asymptote))
	i := time.Now().Sub(lastUpdate).Seconds()
	return 2 * asymptote / math.Pi * math.Atan(i/refindex*f)
}

// randomfloat between 0 and 1
func randomfloat() (float64, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return 0, err
	}
	c := float64(binary.BigEndian.Uint32(b)) / float64(^uint32(0)) // random int / max int
	return c, nil
}

func (client *Client) nonrevCredPrepareCache(credid irma.CredentialTypeIdentifier, index int) error {
	irma.Logger.WithFields(logrus.Fields{"credid": credid, "index": index}).Debug("Preparing cache")
	cred, err := client.credential(credid, index)
	if err != nil {
		return err
	}
	return cred.NonrevPrepareCache()
}

// NonrevPrepare updates the revocation state for each credential in the request
// requiring a nonrevocation proof, using the updates included in the request, or the remote
// revocation server if those do not suffice.
func (client *Client) NonrevPreprare(request irma.SessionRequest) error {
	var err error
	var cred *credential
	var updated bool
	for id := range request.Disclosure().Identifiers().CredentialTypes {
		typ := client.Configuration.CredentialTypes[id]
		if !typ.SupportsRevocation() {
			continue
		}
		attrs := client.attrs(id)
		for i := 0; i < len(attrs); i++ {
			if cred, err = client.credential(id, i); err != nil {
				return err
			}
			if updated, err = cred.NonrevPrepare(client.Configuration, request); err != nil {
				if err == revocation.ErrorRevoked {
					attrs[i].Revoked = true
					cred.AttributeList().Revoked = true
					if serr := client.storage.StoreAttributes(client.attributes); serr != nil {
						client.reportError(serr)
						return err
					}
					client.handler.Revoked(&irma.CredentialIdentifier{
						Type: cred.CredentialType().Identifier(),
						Hash: cred.AttributeList().Hash(),
					})
				}
				return err
			}
			if updated {
				if err = client.storage.StoreSignature(cred); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// nonrevRepopulateCaches repopulates the consumed nonrevocation caches of the credentials involved
// in the request, in background jobs, after the request has finished.
func (client *Client) nonrevRepopulateCaches(request irma.SessionRequest) {
	for id := range request.Disclosure().Identifiers().CredentialTypes {
		typ := client.Configuration.CredentialTypes[id]
		if !typ.SupportsRevocation() {
			continue
		}
		for i, attrs := range client.attrs(id) {
			if attrs.CredentialType() == nil || !attrs.CredentialType().SupportsRevocation() {
				continue
			}
			id := id
			i := i
			client.jobs <- func() {
				if err := client.nonrevCredPrepareCache(id, i); err != nil {
					client.reportError(err)
				}
			}
		}
	}
}

// NonrevPrepare attempts to update the credential's nonrevocation witness from
// 1) the session request, and then 2) the revocation server if our witness is too far out of date.
// Returns whether or not the credential's nonrevocation state was updated. If so the caller should
// persist the updated credential to storage.
func (cred *credential) NonrevPrepare(conf *irma.Configuration, request irma.SessionRequest) (bool, error) {
	credtype := cred.CredentialType().Identifier()
	base := request.Base()
	if !base.RequestsRevocation(credtype) {
		return false, nil
	}

	if err := base.RevocationConsistent(); err != nil {
		return false, err
	}

	// first try to update witness by applying the revocation update messages attached to the session request
	var (
		revupdates = base.RevocationUpdates[credtype][cred.Pk.Counter]
		updated    bool
		err        error
	)
	if revupdates == nil {
		return false, errors.Errorf("revocation updates for key %d not found in session request", cred.Pk.Counter)
	}
	updated, err = cred.NonrevApplyUpdates(revupdates, irma.RevocationKeys{Conf: conf})
	if err != nil {
		return updated, err
	}
	count := len(revupdates.Events)
	if cred.NonRevocationWitness.Accumulator.Index >= revupdates.Events[count-1].Index {
		return updated, nil
	}

	// nonrevocation witness is still out of date after applying the updates from the request:
	// we were too far behind. Update from revocation server.
	return cred.NonrevUpdateFromServer(conf)
}

func (cred *credential) NonrevUpdateFromServer(conf *irma.Configuration) (bool, error) {
	credtype := cred.CredentialType().Identifier()
	revupdates, err := irma.RevocationClient{Conf: conf}.
		FetchUpdateFrom(credtype, cred.Pk.Counter, cred.NonRevocationWitness.Accumulator.Index+1)
	if err != nil {
		return false, err
	}
	return cred.NonrevApplyUpdates(revupdates, irma.RevocationKeys{Conf: conf})
}

// NonrevApplyUpdates updates the credential's nonrevocation witness using the specified messages,
// if they all verify and if their indices are ahead and adjacent to that of our witness.
func (cred *credential) NonrevApplyUpdates(update *revocation.Update, keys irma.RevocationKeys) (bool, error) {
	oldindex := cred.NonRevocationWitness.Accumulator.Index

	pk, err := keys.PublicKey(cred.CredentialType().IssuerIdentifier(), update.SignedAccumulator.PKCounter)
	if err != nil {
		return false, err
	}
	if err = cred.NonRevocationWitness.Update(pk, update); err != nil {
		return false, err
	}

	return cred.NonRevocationWitness.Accumulator.Index != oldindex, nil
}
