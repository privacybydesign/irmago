package irma

import (
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/irmago/internal/common"
)

type (
	// PrivateKeyRing provides access to a set of private keys.
	PrivateKeyRing interface {
		// Latest returns the private key with the highest counter for the specified issuer, if any,
		// or an error.
		Latest(id IssuerIdentifier) (*gabikeys.PrivateKey, error)

		// Get returns the specified private key, or an error.
		Get(id IssuerIdentifier, counter uint) (*gabikeys.PrivateKey, error)

		// Iterate executes the specified function on each private key of the specified issuer
		// present in the ring. The private keys are offered to the function in no particular order,
		// and the same key may be offered multiple times. Returns on the first error returned
		// by the function.
		Iterate(id IssuerIdentifier, f func(sk *gabikeys.PrivateKey) error) error
	}

	// PrivateKeyRingFolder represents a folder on disk containing private keys with filenames
	// of the form scheme.issuer.xml and scheme.issuer.counter.xml.
	PrivateKeyRingFolder struct {
		path string
		conf *Configuration
	}

	// privateKeyRingScheme provides access to private keys present in a scheme.
	privateKeyRingScheme struct {
		conf *Configuration
	}

	// privateKeyRingMerge is a merge of multiple key rings into one, provides access to the
	// private keys of all of them.
	privateKeyRingMerge struct {
		rings []PrivateKeyRing
	}
)

var (
	ErrMissingPrivateKey = fmt.Errorf("issuer private key not found: %w", os.ErrNotExist)
)

func NewPrivateKeyRingFolder(path string, conf *Configuration) (*PrivateKeyRingFolder, error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	ring := &PrivateKeyRingFolder{path, conf}
	for _, file := range files {
		filename := file.Name()
		issuerid, counter, err := ring.parseFilename(filename)
		if err != nil {
			return nil, err
		}
		if issuerid == nil {
			Logger.WithField("file", filename).Infof("Skipping non-private key file encountered in private keys path")
			continue
		}
		sk, err := ring.readFile(filename, *issuerid)
		if err != nil {
			return nil, err
		}
		if counter != nil && *counter != sk.Counter {
			return nil, errors.Errorf("private key %s has wrong counter %d in filename, should be %d", filename, counter, sk.Counter)
		}
	}
	return ring, nil
}

func (*PrivateKeyRingFolder) parseFilename(filename string) (*IssuerIdentifier, *uint, error) {
	// This regexp returns one of the following:
	// [ "foo.bar.xml", "foo.bar", "", "" ] in case of "foo.bar.xml"
	// [ "foo.bar.xml", "foo.bar", ".2", "2" ] in case of "foo.bar.2.xml"
	// nil in case of other files.
	matches := regexp.MustCompile(`^([^.]+\.[^.]+)(\.(\d+))?\.xml$`).FindStringSubmatch(filename)

	if len(matches) != 4 {
		return nil, nil, nil
	}
	issuerid := NewIssuerIdentifier(matches[1])
	if matches[3] == "" {
		return &issuerid, nil, nil
	}
	counter, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return nil, nil, err
	}
	c := uint(counter)
	return &issuerid, &c, nil
}

func (p *PrivateKeyRingFolder) readFile(filename string, id IssuerIdentifier) (*gabikeys.PrivateKey, error) {
	scheme := p.conf.SchemeManagers[id.SchemeManagerIdentifier()]
	if scheme == nil {
		return nil, errors.Errorf("Private key of issuer %s belongs to unknown scheme", id.String())
	}
	sk, err := gabikeys.NewPrivateKeyFromFile(filepath.Join(p.path, filename), scheme.Demo)
	if err != nil {
		return nil, err
	}
	if err = validatePrivateKey(id, sk, p.conf); err != nil {
		return nil, err
	}
	return sk, nil
}

func (p *PrivateKeyRingFolder) Get(id IssuerIdentifier, counter uint) (*gabikeys.PrivateKey, error) {
	sk, err := p.readFile(fmt.Sprintf("%s.%d.xml", id.String(), counter), id)
	if err != nil && !goerrors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if sk != nil {
		return sk, nil
	}
	sk, err = p.readFile(fmt.Sprintf("%s.xml", id.String()), id)
	if err != nil {
		return nil, err
	}
	if counter != sk.Counter {
		return nil, ErrMissingPrivateKey
	}
	return sk, nil
}

func (p *PrivateKeyRingFolder) Latest(id IssuerIdentifier) (*gabikeys.PrivateKey, error) {
	var sk *gabikeys.PrivateKey
	if err := p.Iterate(id, func(s *gabikeys.PrivateKey) error {
		if sk == nil || s.Counter > sk.Counter {
			sk = s
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, ErrMissingPrivateKey
	}
	return sk, nil
}

func (p *PrivateKeyRingFolder) Iterate(id IssuerIdentifier, f func(sk *gabikeys.PrivateKey) error) error {
	files, err := filepath.Glob(filepath.Join(p.path, fmt.Sprintf("%s.*.xml", id.String())))
	if err != nil {
		return err
	}
	fileWithoutCounter := filepath.Join(p.path, fmt.Sprintf("%s.xml", id.String()))
	exists, err := common.PathExists(fileWithoutCounter)
	if err != nil {
		return err
	}
	if exists {
		files = append(files, fileWithoutCounter)
	}
	for _, file := range files {
		sk, err := p.readFile(filepath.Base(file), id)
		if err != nil {
			return err
		}
		if err = f(sk); err != nil {
			return err
		}
	}
	return nil
}

func newPrivateKeyRingScheme(conf *Configuration) (*privateKeyRingScheme, error) {
	ring := &privateKeyRingScheme{conf}
	if err := validatePrivateKeyRing(ring, conf); err != nil {
		return nil, err
	}
	return ring, nil
}

func (p *privateKeyRingScheme) counters(issuerid IssuerIdentifier) (i []uint, err error) {
	scheme := p.conf.SchemeManagers[issuerid.SchemeManagerIdentifier()]
	return matchKeyPattern(filepath.Join(scheme.path(), issuerid.Name(), "PrivateKeys", "*"))
}

func (p *privateKeyRingScheme) Get(id IssuerIdentifier, counter uint) (*gabikeys.PrivateKey, error) {
	schemeID := id.SchemeManagerIdentifier()
	scheme := p.conf.SchemeManagers[schemeID]
	if scheme == nil {
		return nil, errors.Errorf("Private key of issuer %s belongs to unknown scheme", id.String())
	}
	file := filepath.Join(scheme.path(), id.Name(), "PrivateKeys", strconv.FormatUint(uint64(counter), 10)+".xml")
	sk, err := gabikeys.NewPrivateKeyFromFile(file, scheme.Demo)
	if err != nil {
		return nil, err
	}
	if sk.Counter != counter {
		return nil, errors.Errorf("Private key %s of issuer %s has wrong <Counter>", file, id.String())
	}
	if err = validatePrivateKey(id, sk, p.conf); err != nil {
		return nil, err
	}
	return sk, nil
}

func (p *privateKeyRingScheme) Latest(id IssuerIdentifier) (*gabikeys.PrivateKey, error) {
	counters, err := p.counters(id)
	if err != nil {
		return nil, err
	}
	if len(counters) == 0 {
		return nil, ErrMissingPrivateKey
	}
	return p.Get(id, counters[len(counters)-1])
}

func (p *privateKeyRingScheme) Iterate(id IssuerIdentifier, f func(sk *gabikeys.PrivateKey) error) error {
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

func (p *privateKeyRingMerge) Get(id IssuerIdentifier, counter uint) (*gabikeys.PrivateKey, error) {
	for _, ring := range p.rings {
		sk, err := ring.Get(id, counter)
		if err == nil {
			return sk, nil
		}
		if !goerrors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return nil, ErrMissingPrivateKey
}

func (p *privateKeyRingMerge) Latest(id IssuerIdentifier) (*gabikeys.PrivateKey, error) {
	var sk *gabikeys.PrivateKey
	for _, ring := range p.rings {
		s, err := ring.Latest(id)
		if err != nil && !goerrors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if s != nil && (sk == nil || s.Counter > sk.Counter) {
			sk = s
		}
	}
	if sk == nil {
		return nil, ErrMissingPrivateKey
	}
	return sk, nil
}

func (p *privateKeyRingMerge) Iterate(id IssuerIdentifier, f func(sk *gabikeys.PrivateKey) error) error {
	for _, ring := range p.rings {
		if err := ring.Iterate(id, f); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateKey(issuerid IssuerIdentifier, sk *gabikeys.PrivateKey, conf *Configuration) error {
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
		msg := fmt.Sprintf("revocation support of private key %d of issuer %s is not consistent with corresponding public key", sk.Counter, issuerid.String())
		if conf.SchemeManagers[issuerid.SchemeManagerIdentifier()].Demo {
			Logger.Warn(msg)
		} else {
			return errors.Errorf(msg)
		}
	}
	return nil
}

func validatePrivateKeyRing(ring PrivateKeyRing, conf *Configuration) error {
	for issuerid := range conf.Issuers {
		err := ring.Iterate(issuerid, func(sk *gabikeys.PrivateKey) error {
			return validatePrivateKey(issuerid, sk, conf)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
