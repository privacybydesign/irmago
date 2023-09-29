package keysharecore

import (
	"sync"

	"github.com/privacybydesign/gabi/big"
)

type MemoryConsistentStorage struct {
	// Commit values generated in first step of keyshare protocol
	commitmentData  map[uint64]*big.Int
	commitmentMutex sync.Mutex

	// Authorization challenges
	authChallenges      map[string][]byte
	authChallengesMutex sync.Mutex
}

func NewMemoryConsistentStorage() *MemoryConsistentStorage {
	return &MemoryConsistentStorage{
		commitmentData: make(map[uint64]*big.Int),
		authChallenges: make(map[string][]byte),
	}
}

func (m *MemoryConsistentStorage) StoreCommitment(id uint64, commitment *big.Int) error {
	m.commitmentMutex.Lock()
	defer m.commitmentMutex.Unlock()

	// TODO: if a commitment is not consumed, it will stay in memory forever.
	m.commitmentData[id] = commitment
	return nil
}

func (m *MemoryConsistentStorage) ConsumeCommitment(id uint64) (*big.Int, error) {
	m.commitmentMutex.Lock()
	defer m.commitmentMutex.Unlock()

	commitment, ok := m.commitmentData[id]
	if !ok {
		return nil, ErrUnknownCommit
	}
	delete(m.commitmentData, id)
	return commitment, nil
}

func (m *MemoryConsistentStorage) StoreAuthChallenge(id []byte, challenge []byte) error {
	m.authChallengesMutex.Lock()
	defer m.authChallengesMutex.Unlock()

	// TODO: if a challenge is not consumed, it will stay in memory forever.
	m.authChallenges[string(id)] = challenge
	return nil
}

func (m *MemoryConsistentStorage) ConsumeAuthChallenge(id []byte) ([]byte, error) {
	m.authChallengesMutex.Lock()
	defer m.authChallengesMutex.Unlock()

	challenge, ok := m.authChallenges[string(id)]
	if !ok {
		return nil, ErrInvalidChallenge
	}
	delete(m.authChallenges, string(id))
	return challenge, nil
}
