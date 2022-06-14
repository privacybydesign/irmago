package irmaclient

import (
	"crypto/rand"
	"encoding/binary"

	"fmt"
	"math"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

func (client *Client) initRevocation() {
	// For every credential supporting revocation, compute nonrevocation caches in async jobs
	for id, attrsets := range client.attributes {
		for i, attrs := range attrsets {
			if attrs.CredentialType() == nil || !attrs.CredentialType().RevocationSupported() {
				continue
			}
			id := id // make copy of same name to capture the value for closure below
			i := i   // see https://golang.org/doc/faq#closures_and_goroutines
			client.jobs <- func() {
				if err := client.nonrevPrepareCache(id, i); err != nil {
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
	_, err := client.Configuration.Scheduler.Every(irma.RevocationParameters.ClientUpdateInterval).Seconds().Do(func() {
		for id, attrsets := range client.attributes {
			for i, attrs := range attrsets {
				if attrs.CredentialType() == nil || !attrs.CredentialType().RevocationSupported() {
					continue
				}
				cred, err := client.credential(id, i)
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
				speed := attrs.CredentialType().RevocationUpdateSpeed * 60 * 60
				p := probability(cred.NonRevocationWitness.Updated, speed)
				if r < p {
					irma.Logger.WithFields(logrus.Fields{
						"random":      r,
						"prob":        p,
						"lastupdated": time.Now().Sub(cred.NonRevocationWitness.Updated).Seconds(),
						"credtype":    id,
						"hash":        attrs.Hash(),
					}).Debug("scheduling nonrevocation witness remote update")
					id := id // copy for closure below (https://golang.org/doc/faq#closures_and_goroutines)
					client.jobs <- func() {
						if err = client.NonrevUpdateFromServer(id); err != nil {
							client.reportError(err)
							return
						}
					}
				}
			}
		}
	})
	if err != nil {
		panic(err) // Indicates wrong usage of gocron, panic so we see it during unit tests
	}
}

// NonrevPrepare updates the revocation state for each credential in the request
// requiring a nonrevocation proof, using the updates included in the request, or the remote
// revocation server if those do not suffice.
func (client *Client) NonrevPrepare(request irma.SessionRequest) error {
	base := request.Base()
	var err error
	var wg sync.WaitGroup
	for id := range request.Disclosure().Identifiers().CredentialTypes {
		credtype := client.Configuration.CredentialTypes[id]
		if !credtype.RevocationSupported() {
			continue
		}
		if !base.RequestsRevocation(id) {
			continue
		}
		irma.Logger.WithField("credtype", id).Debug("updating witnesses")
		wg.Add(1)
		id := id // copy for closure below (https://golang.org/doc/faq#closures_and_goroutines)
		go func() {
			if e := client.nonrevUpdate(id, base.Revocation[id].Updates); e != nil {
				err = e // overwrites err from previously finished call, if any
			}
			wg.Done()
		}()
	}
	wg.Wait()
	return err
}

// nonrevUpdate updates all contained instances of the specified type, using the specified
// updates if present and if they suffice, and contacting the issuer's server to download updates
// otherwise.
func (client *Client) nonrevUpdate(id irma.CredentialTypeIdentifier, updates map[uint]*revocation.Update) error {
	lowest := map[uint]uint64{}
	attrs := client.attrs(id)

	// Per credential and issuer key counter we may possess multiple credential instances.
	// Of the nonrevocation witnesses of these, take the lowest index.
	for i := 0; i < len(attrs); i++ {
		cred, err := client.credential(id, i)
		if err != nil {
			return err
		}
		if cred.NonRevocationWitness == nil {
			continue
		}
		pkid := cred.Pk.Counter
		l, present := lowest[pkid]
		if !present || cred.NonRevocationWitness.SignedAccumulator.Accumulator.Index < l {
			lowest[pkid] = cred.NonRevocationWitness.SignedAccumulator.Accumulator.Index
		}
	}

	// For each key counter, get an update message starting at the lowest index computed above,
	// that can update all of our credential instance of the given type and key counter,
	// using the specified update messags if they suffice, or the issuer's server otherwise.
	u := map[uint]*revocation.Update{}
	for counter, l := range lowest {
		update := updates[counter]
		if updates != nil && (update == nil || len(update.Events) == 0) {
			return errors.Errorf("missing revocation update for %s-%d", id, counter)
		}
		if update != nil && update.Events[0].Index <= l+1 {
			u[counter] = update
		} else {
			var err error
			u[counter], err = irma.RevocationClient{Conf: client.Configuration}.
				FetchUpdateFrom(id, counter, l+1)
			if err != nil {
				return err
			}
		}
	}

	// Apply the update messages to all instances of the given type and key counter
	for counter, update := range u {
		if err := client.nonrevApplyUpdates(id, counter, update); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) nonrevApplyUpdates(id irma.CredentialTypeIdentifier, counter uint, update *revocation.Update) error {
	client.credMutex.Lock()
	defer client.credMutex.Unlock()

	attrs := client.attrs(id)
	var save bool
	for i := 0; i < len(attrs); i++ {
		cred, err := client.credential(id, i)
		if err != nil {
			return err
		}
		if cred.NonRevocationWitness == nil || cred.Pk.Counter != counter {
			continue
		}
		updated, err := cred.nonrevApplyUpdates(update, irma.RevocationKeys{Conf: client.Configuration})
		if updated {
			save = true
			if err = client.storage.StoreSignature(cred); err != nil {
				return err
			}
		}
		if err == revocation.ErrorRevoked {
			id := cred.CredentialType().Identifier()
			hash := cred.attrs.Hash()
			irma.Logger.Warnf("credential %s %s revoked", id, hash)
			attrs[i].Revoked = true
			cred.attrs.Revoked = true
			save = true
			client.handler.Revoked(&irma.CredentialIdentifier{Type: id, Hash: hash})
			// Even if this credential is revoked during a session, we may have
			// other instances that can satisfy the request. So don't return an
			// error which would halt the session.
			continue
		}
		if err != nil {
			return err
		}
		// Asynchroniously update nonrevocation proof cache from updated witness
		irma.Logger.WithField("credtype", id).Debug("scheduling nonrevocation cache update")
		go func(cred *credential) {
			if err := cred.NonrevPrepareCache(); err != nil {
				client.reportError(err)
			}
		}(cred)
	}
	if save {
		if err := client.storage.StoreAttributes(id, client.attributes[id]); err != nil {
			client.reportError(err)
			return err
		}
	}
	return nil
}

func (client *Client) NonrevUpdateFromServer(id irma.CredentialTypeIdentifier) error {
	return client.nonrevUpdate(id, nil)
}

func (client *Client) nonrevPrepareCache(id irma.CredentialTypeIdentifier, index int) error {
	logger := irma.Logger.WithFields(logrus.Fields{"credtype": id, "index": index})
	logger.Debug("preparing cache")
	defer logger.Debug("Preparing cache done")
	cred, err := client.credential(id, index)
	if err != nil {
		return err
	}
	return cred.NonrevPrepareCache()
}

// nonrevRepopulateCaches repopulates the consumed nonrevocation caches of the credentials involved
// in the request, in background jobs, after the request has finished.
func (client *Client) nonrevRepopulateCaches(request irma.SessionRequest) {
	for id := range request.Disclosure().Identifiers().CredentialTypes {
		credtype := client.Configuration.CredentialTypes[id]
		if credtype == nil || !credtype.RevocationSupported() {
			continue
		}
		for i := range client.attrs(id) {
			id := id
			i := i
			client.jobs <- func() {
				if err := client.nonrevPrepareCache(id, i); err != nil {
					client.reportError(err)
				}
			}
		}
	}
}

// nonrevApplyUpdates updates the credential's nonrevocation witness using the specified messages,
// if they all verify and if their indices are ahead and adjacent to that of our witness.
func (cred *credential) nonrevApplyUpdates(update *revocation.Update, keys irma.RevocationKeys) (bool, error) {
	t := cred.NonRevocationWitness.SignedAccumulator.Accumulator.Time

	pk, err := keys.PublicKey(cred.CredentialType().IssuerIdentifier(), update.SignedAccumulator.PKCounter)
	if err != nil {
		return false, err
	}
	logger := irma.Logger.WithFields(logrus.Fields{"credtype": cred.CredentialType().Identifier(), "hash": cred.attrs.Hash()})
	logger.Debugf("updating witness")
	defer logger.Debug("updating witness done")
	if err = cred.NonRevocationWitness.Update(pk, update); err != nil {
		return false, err
	}

	return cred.NonRevocationWitness.SignedAccumulator.Accumulator.Time != t, nil
}

// probability returns a float between 0 and asymptote, representing a probability
// that asymptotically increases to the asymptote, reaching
// a reference probability at a reference index.
func probability(lastUpdate time.Time, refindex uint64) float64 {
	const (
		asymptote      = 1.0 / 3          // max probability
		refprobability = 0.75 * asymptote // probability after one week
	)
	f := math.Tan(math.Pi * refprobability / (2 * asymptote))
	i := time.Now().Sub(lastUpdate).Seconds()
	return 2 * asymptote / math.Pi * math.Atan(i/float64(refindex)*f)
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
