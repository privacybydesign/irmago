package irma

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type (
	// PrivateKeyRing provides access to a set of private keys.
	PrivateKeyRing interface {
		// Latest returns the private key with the highest counter for the specified issuer, if any,
		// or an error.
		Latest(id IssuerIdentifier) (*gabi.PrivateKey, error)

		// Get returns the specified private key, or an error.
		Get(id IssuerIdentifier, counter uint) (*gabi.PrivateKey, error)

		// Iterate executes the specified function on each private key of the specified issuer
		// present in the ring. The private keys are offered to the function in no particular order,
		// and the same key may be offered multiple times. Returns on the first error returned
		// by the function.
		Iterate(id IssuerIdentifier, f func(sk *gabi.PrivateKey) error) error
	}

	// PrivateKeyRingFolder represents a folder on disk containing private keys with filenames
	// of the form scheme.issuer.xml and scheme.issuer.counter.xml.
	PrivateKeyRingFolder struct {
		path string
	}

	// privateKeyRingScheme provides access to private keys present in a scheme.
	privateKeyRingScheme struct {
		path string
	}

	// privateKeyRingMerge is a merge of multiple key rings into one, provides access to the
	// private keys of all of them.
	privateKeyRingMerge struct {
		rings []PrivateKeyRing
	}
)

func NewPrivateKeyRingFolder(path string, conf *Configuration) (*PrivateKeyRingFolder, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	ring := &PrivateKeyRingFolder{path}
	for _, file := range files {
		filename := file.Name()
		dotcount := strings.Count(filename, ".")
		// filename format may be scheme.issuer.xml or scheme.issuer.counter.xml; skip any other file
		if filepath.Ext(filename) != ".xml" || filename[0] == '.' || dotcount < 2 || dotcount > 3 {
			Logger.WithField("file", filename).Infof("Skipping non-private key file encountered in private keys path")
			continue
		}
		counter := -1
		base := strings.TrimSuffix(filename, filepath.Ext(filename)) // strip .xml
		if dotcount == 3 {
			index := strings.LastIndex(base, ".")
			counter, err = strconv.Atoi(base[index+1:])
			base = base[:index]
		}
		sk, err := ring.readFile(filename)
		if err != nil {
			return nil, err
		}
		if counter >= 0 && uint(counter) != sk.Counter {
			return nil, errors.Errorf("private key %s has wrong counter %d in filename, should be %d", filename, counter, sk.Counter)
		}
		if err = validatePrivateKey(NewIssuerIdentifier(base), sk, conf); err != nil {
			return nil, err
		}
	}
	return ring, nil
}

func (p *PrivateKeyRingFolder) readFile(filename string) (*gabi.PrivateKey, error) {
	return gabi.NewPrivateKeyFromFile(filepath.Join(p.path, filename))
}

func (p *PrivateKeyRingFolder) Get(id IssuerIdentifier, counter uint) (*gabi.PrivateKey, error) {
	sk, err := p.readFile(fmt.Sprintf("%s.%d.xml", id.String(), counter))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if sk != nil {
		return sk, nil
	}
	sk, err = p.readFile(fmt.Sprintf("%s.xml", id.String()))
	if err != nil {
		return nil, err
	}
	if counter != sk.Counter {
		return nil, os.ErrNotExist
	}
	return sk, nil
}

func (p *PrivateKeyRingFolder) Latest(id IssuerIdentifier) (*gabi.PrivateKey, error) {
	var sk *gabi.PrivateKey
	if err := p.Iterate(id, func(s *gabi.PrivateKey) error {
		if sk == nil || s.Counter > sk.Counter {
			sk = s
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, os.ErrNotExist
	}
	return sk, nil
}

func (p *PrivateKeyRingFolder) Iterate(id IssuerIdentifier, f func(sk *gabi.PrivateKey) error) error {
	files, err := filepath.Glob(filepath.Join(p.path, fmt.Sprintf("%s*", id.String())))
	if err != nil {
		return err
	}
	for _, file := range files {
		sk, err := p.readFile(filepath.Base(file))
		if err != nil {
			return err
		}
		if err = f(sk); err != nil {
			return err
		}
	}
	return nil
}

func newPrivateKeyRingScheme(path string, conf *Configuration) (*privateKeyRingScheme, error) {
	ring := &privateKeyRingScheme{path}
	err := validatePrivateKeyRing(ring, conf)
	if err != nil {
		return nil, err
	}
	return ring, nil
}

func (p *privateKeyRingScheme) counters(issuerid IssuerIdentifier) (i []uint, err error) {
	return matchKeyPattern(p.path, issuerid, privkeyPattern)
}

func (p *privateKeyRingScheme) Get(id IssuerIdentifier, counter uint) (*gabi.PrivateKey, error) {
	path := fmt.Sprintf(privkeyPattern, p.path, id.SchemeManagerIdentifier().Name(), id.Name())
	file := strings.Replace(path, "*", strconv.FormatUint(uint64(counter), 10), 1)
	sk, err := gabi.NewPrivateKeyFromFile(file)
	if err != nil {
		return nil, err
	}
	if sk.Counter != counter {
		return nil, errors.Errorf("Private key %s of issuer %s has wrong <Counter>", file, id.String())
	}
	return sk, nil
}

func (p *privateKeyRingScheme) Latest(id IssuerIdentifier) (*gabi.PrivateKey, error) {
	counters, err := p.counters(id)
	if err != nil {
		return nil, err
	}
	if len(counters) == 0 {
		return nil, os.ErrNotExist
	}
	return p.Get(id, counters[len(counters)-1])
}

func (p *privateKeyRingScheme) Iterate(id IssuerIdentifier, f func(sk *gabi.PrivateKey) error) error {
	indices, err := p.counters(id)
	if err != nil {
		return err
	}
	for _, counter := range indices {
		sk, err := p.Get(id, counter)
		if err != nil {
			return err
		}
		if err = f(sk); err != nil {
			return err
		}
	}
	return nil
}

func (p *privateKeyRingMerge) Add(ring PrivateKeyRing) {
	p.rings = append(p.rings, ring)
}

func (p *privateKeyRingMerge) Get(id IssuerIdentifier, counter uint) (*gabi.PrivateKey, error) {
	for _, ring := range p.rings {
		sk, err := ring.Get(id, counter)
		if err == nil {
			return sk, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return nil, os.ErrNotExist
}

func (p *privateKeyRingMerge) Latest(id IssuerIdentifier) (*gabi.PrivateKey, error) {
	var sk *gabi.PrivateKey
	for _, ring := range p.rings {
		s, err := ring.Latest(id)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if s != nil && (sk == nil || s.Counter > sk.Counter) {
			sk = s
		}
	}
	if sk == nil {
		return nil, os.ErrNotExist
	}
	return sk, nil
}

func (p *privateKeyRingMerge) Iterate(id IssuerIdentifier, f func(sk *gabi.PrivateKey) error) error {
	for _, ring := range p.rings {
		if err := ring.Iterate(id, f); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateKey(issuerid IssuerIdentifier, sk *gabi.PrivateKey, conf *Configuration) error {
	if _, ok := conf.Issuers[issuerid]; !ok {
		return errors.Errorf("Private key %d of issuer %s belongs to an unknown issuer", sk.Counter, issuerid.String())
	}
	pk, err := conf.PublicKey(issuerid, sk.Counter)
	if err != nil {
		return err
	}
	if pk == nil {
		return errors.Errorf("Private key %d of issuer %s has no corresponding public key", sk.Counter, issuerid.String())
	}
	if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
		return errors.Errorf("Private key %d of issuer %s does not belong to corresponding public key", sk.Counter, issuerid.String())
	}
	if sk.RevocationSupported() != pk.RevocationSupported() {
		return errors.Errorf("revocation support of private key %d of issuer %s is not consistent with corresponding public key", sk.Counter, issuerid.String())
	}
	return nil
}

func validatePrivateKeyRing(ring PrivateKeyRing, conf *Configuration) error {
	for issuerid := range conf.Issuers {
		err := ring.Iterate(issuerid, func(sk *gabi.PrivateKey) error {
			return validatePrivateKey(issuerid, sk, conf)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
