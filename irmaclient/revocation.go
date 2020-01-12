package irmaclient

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

const nonrevUpdateInterval = 10 // Once every 10 seconds

func (client *Client) initRevocation() {
	// For every credential supporting revocation, compute nonrevocation caches in async jobs
	for typ, attrsets := range client.attributes {
		for i, attrs := range attrsets {
			if attrs.CredentialType() == nil || !attrs.CredentialType().SupportsRevocation() {
				continue
			}
			typ := typ // make copy of same name to capture the value for closure below
			i := i     // see https://golang.org/doc/faq#closures_and_goroutines
			client.jobs <- func() {
				if err := client.nonrevPrepareCache(typ, i); err != nil {
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
		for typ, attrsets := range client.attributes {
			for i, attrs := range attrsets {
				if attrs.CredentialType() == nil || !attrs.CredentialType().SupportsRevocation() {
					continue
				}
				cred, err := client.credential(typ, i)
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
					irma.Logger.Debugf("scheduling nonrevocation witness remote update for %s-%d", typ, i)
					client.jobs <- func() {
						if err = client.nonrevUpdateFromServer(typ); err != nil {
							client.reportError(err)
							return
						}
					}
				}
			}
		}
	})
}

// NonrevPrepare updates the revocation state for each credential in the request
// requiring a nonrevocation proof, using the updates included in the request, or the remote
// revocation server if those do not suffice.
func (client *Client) NonrevPrepare(request irma.SessionRequest) error {
	base := request.Base()
	if err := base.RevocationConsistent(); err != nil {
		return err
	}

	for typ := range request.Disclosure().Identifiers().CredentialTypes {
		credtype := client.Configuration.CredentialTypes[typ]
		if !credtype.SupportsRevocation() {
			continue
		}
		if !base.RequestsRevocation(typ) {
			continue
		}
		if err := client.nonrevUpdate(typ, base.RevocationUpdates[typ]); err != nil {
			return err
		}
	}
	return nil
}

// nonrevUpdate updates all contained instances of the specified type, using the specified
// updates if present and if they suffice, and contacting the issuer's server to download updates
// otherwise.
func (client *Client) nonrevUpdate(typ irma.CredentialTypeIdentifier, updates map[uint]*revocation.Update) error {
	lowest := map[uint]uint64{}
	attrs := client.attrs(typ)

	// Per credential and issuer key counter we may posess multiple credential instances.
	// Of the nonrevocation witnesses of these, take the lowest index.
	for i := 0; i < len(attrs); i++ {
		cred, err := client.credential(typ, i)
		if err != nil {
			return err
		}
		if cred.NonRevocationWitness == nil {
			continue
		}
		pkid := cred.Pk.Counter
		_, present := lowest[pkid]
		if !present || cred.NonRevocationWitness.Accumulator.Index < lowest[pkid] {
			lowest[pkid] = cred.NonRevocationWitness.Accumulator.Index
		}
	}

	// For each key counter, get an update message starting at the lowest index computed above,
	// that can update all of our credential instance of the given type and key counter,
	// using the specified update messags if they suffice, or the issuer's server otherwise.
	u := map[uint]*revocation.Update{}
	for counter, l := range lowest {
		update := updates[counter]
		if update != nil && len(update.Events) > 0 && update.Events[0].Index <= l+1 {
			u[counter] = update
		} else {
			var err error
			u[counter], err = irma.RevocationClient{Conf: client.Configuration}.
				FetchUpdateFrom(typ, counter, l+1)
			if err != nil {
				return err
			}
		}
	}

	// Apply the update messages to all instances of the given type and key counter
	for counter, update := range u {
		if err := client.nonrevApplyUpdates(typ, counter, update); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) nonrevApplyUpdates(typ irma.CredentialTypeIdentifier, counter uint, update *revocation.Update) error {
	attrs := client.attrs(typ)
	var save bool
	for i := 0; i < len(attrs); i++ {
		cred, err := client.credential(typ, i)
		if err != nil {
			return err
		}
		if cred.NonRevocationWitness == nil || cred.Pk.Counter != counter {
			continue
		}
		updated, err := cred.nonrevApplyUpdates(update, irma.RevocationKeys{Conf: client.Configuration})
		if updated {
			save = true
		}
		if err == revocation.ErrorRevoked {
			attrs[i].Revoked = true
			cred.attrs.Revoked = true
			save = true
			client.handler.Revoked(&irma.CredentialIdentifier{
				Type: cred.CredentialType().Identifier(),
				Hash: cred.attrs.Hash(),
			})
			// Even if this credential is revoked during a session, we may have
			// other instances that can satisfy the request. So don't return an
			// error which would halt the session.
			continue
		}
		if err != nil {
			return err
		}
	}
	if save {
		if err := client.storage.StoreAttributes(client.attributes); err != nil {
			client.reportError(err)
			return err
		}
	}
	return nil
}

func (client *Client) nonrevUpdateFromServer(typ irma.CredentialTypeIdentifier) error {
	if err := client.nonrevUpdate(typ, map[uint]*revocation.Update{}); err != nil {
		return err
	}
	return nil
}

func (client *Client) nonrevPrepareCache(typ irma.CredentialTypeIdentifier, index int) error {
	irma.Logger.WithFields(logrus.Fields{"credtype": typ, "index": index}).Debug("Preparing cache")
	cred, err := client.credential(typ, index)
	if err != nil {
		return err
	}
	return cred.NonrevPrepareCache()
}

// nonrevRepopulateCaches repopulates the consumed nonrevocation caches of the credentials involved
// in the request, in background jobs, after the request has finished.
func (client *Client) nonrevRepopulateCaches(request irma.SessionRequest) {
	for typ := range request.Disclosure().Identifiers().CredentialTypes {
		credtype := client.Configuration.CredentialTypes[typ]
		if !credtype.SupportsRevocation() {
			continue
		}
		for i := range client.attrs(typ) {
			typ := typ
			i := i
			client.jobs <- func() {
				if err := client.nonrevPrepareCache(typ, i); err != nil {
					client.reportError(err)
				}
			}
		}
	}
}

// nonrevApplyUpdates updates the credential's nonrevocation witness using the specified messages,
// if they all verify and if their indices are ahead and adjacent to that of our witness.
func (cred *credential) nonrevApplyUpdates(update *revocation.Update, keys irma.RevocationKeys) (bool, error) {
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
