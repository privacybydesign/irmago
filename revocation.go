package irma

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/privacybydesign/gabi/revocation"
)

func (conf *Configuration) RevocationKeystore(issuerid IssuerIdentifier) revocation.Keystore {
	return &issuerKeystore{issid: issuerid, conf: conf}
}

// issuerKeystore implements revocation.Keystore.
type issuerKeystore struct {
	issid IssuerIdentifier
	conf  *Configuration
}

var _ revocation.Keystore = (*issuerKeystore)(nil)

func (ks *issuerKeystore) PublicKey(counter uint) (*revocation.PublicKey, error) {
	pk, err := ks.conf.PublicKey(ks.issid, int(counter))
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.Errorf("public key %d of issuer %s not found", counter, ks.issid)
	}
	if !pk.RevocationSupported() {
		return nil, errors.Errorf("public key %d of issuer %s does not support revocation", counter, ks.issid)
	}
	rpk, err := pk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return rpk, nil
}

func (conf *Configuration) RevocationGetUpdates(credid CredentialTypeIdentifier, index uint64) ([]*revocation.Record, error) {
	var records []*revocation.Record
	err := NewHTTPTransport(conf.CredentialTypes[credid].RevocationServer).
		Get(fmt.Sprintf("-/revocation/records/%s/%d", credid, index), &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (conf *Configuration) RevocationUpdateAll() error {
	var err error
	for credid := range conf.revDBs {
		if err = conf.RevocationUpdateDB(credid); err != nil {
			return err
		}
	}
	return nil
}

func (conf *Configuration) RevocationSetRecords(b *BaseRequest) error {
	if len(b.Revocation) == 0 {
		return nil
	}
	b.RevocationUpdates = make(map[CredentialTypeIdentifier][]*revocation.Record, len(b.Revocation))
	for _, credid := range b.Revocation {
		db, err := conf.RevocationDB(credid)
		if err != nil {
			return err
		}
		if err = conf.revocationUpdateDelayed(credid, db); err != nil {
			return err
		}
		b.RevocationUpdates[credid], err = db.LatestRecords(revocationUpdateCount)
		if err != nil {
			return err
		}
	}
	return nil
}

func (conf *Configuration) RevocationUpdateDB(credid CredentialTypeIdentifier) error {
	db, err := conf.RevocationDB(credid)
	if err != nil {
		return err
	}
	var index uint64
	if db.Enabled() {
		index = db.Current.Index + 1
	}
	records, err := conf.RevocationGetUpdates(credid, index)
	if err != nil {
		return err
	}
	return db.AddRecords(records)
}

func (conf *Configuration) RevocationDB(credid CredentialTypeIdentifier) (*revocation.DB, error) {
	if _, known := conf.CredentialTypes[credid]; !known {
		return nil, errors.New("unknown credential type")
	}
	if conf.revDBs == nil {
		conf.revDBs = make(map[CredentialTypeIdentifier]*revocation.DB)
	}
	if conf.revDBs[credid] == nil {
		var err error
		db, err := revocation.LoadDB(
			filepath.Join(conf.RevocationPath, credid.String()),
			conf.RevocationKeystore(credid.IssuerIdentifier()),
		)
		if err != nil {
			return nil, err
		}
		conf.revDBs[credid] = db
	}
	return conf.revDBs[credid], nil
}

func (conf *Configuration) revocationUpdateDelayed(credid CredentialTypeIdentifier, db *revocation.DB) error {
	if db.Updated.Before(time.Now().Add(-5 * time.Minute)) {
		if err := conf.RevocationUpdateDB(credid); err != nil {
			return err
		}
	}
	return nil
}

func (conf *Configuration) Revoke(credid CredentialTypeIdentifier, key string) error {
	sk, err := conf.PrivateKey(credid.IssuerIdentifier())
	if err != nil {
		return err
	}
	if sk == nil {
		return errors.New("private key not found")
	}
	rsk, err := sk.RevocationKey()
	if err != nil {
		return err
	}

	db, err := conf.RevocationDB(credid)
	if err != nil {
		return err
	}
	return db.Revoke(rsk, []byte(key))
}

func (conf *Configuration) Close() error {
	merr := &multierror.Error{}
	var err error
	for _, db := range conf.revDBs {
		if err = db.Close(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	conf.revDBs = nil
	return merr.ErrorOrNil()
}
