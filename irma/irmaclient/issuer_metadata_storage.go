package irmaclient

import (
	"fmt"

	"github.com/privacybydesign/irmago/irma"
)

type IssuerMetadata struct {
	IssuerId   string
	Name       irma.TranslatedString
	LogoPath   irma.TranslatedString
	WebsiteUrl irma.TranslatedString
	Parent     *IssuerMetadata
}

type IssuerMetadataStorage interface {
	Add(iss *IssuerMetadata) error
	Remove(issuerId string) error
	Get(issuerId string) (*IssuerMetadata, error)
	RemoveAll() error
}

// ==============================================================

type InMemoryIssuerMetadataStorage struct {
	issuers map[string]*IssuerMetadata
}

func NewInMemoryIssuerMetadataStorage() IssuerMetadataStorage {
	return &InMemoryIssuerMetadataStorage{
		issuers: map[string]*IssuerMetadata{},
	}
}

func (s *InMemoryIssuerMetadataStorage) Add(iss *IssuerMetadata) error {
	s.issuers[iss.IssuerId] = iss
	return nil
}

func (s *InMemoryIssuerMetadataStorage) Remove(issuerId string) error {
	_, ok := s.issuers[issuerId]
	if !ok {
		return fmt.Errorf("tried to remove non-existing issuer with id '%s'", issuerId)
	}
	return nil
}

func (s *InMemoryIssuerMetadataStorage) Get(issuerId string) (*IssuerMetadata, error) {
	result, ok := s.issuers[issuerId]
	if !ok {
		return nil, fmt.Errorf("failed to get non-existing issuer with id '%s'", issuerId)
	}
	return result, nil
}

func (s *InMemoryIssuerMetadataStorage) RemoveAll() error {
	s.issuers = map[string]*IssuerMetadata{}
	return nil
}

// ==============================================================
