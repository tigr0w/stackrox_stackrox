package manager

import (
	"context"
	"time"

	"github.com/stackrox/rox/central/hash/datastore"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sync"
)

const (
	flushInterval = 1 * time.Minute
)

var (
	log = logging.LoggerForModule()
)

// Manager is a hash manager that provides access to cluster-based dedupers and persists
// the hashes into the database
type Manager interface {
	Start(ctx context.Context)

	GetDeduper(ctx context.Context, clusterID string) Deduper
	Delete(ctx context.Context, clusterID string) error
}

// NewManager instantiates a Manager
func NewManager(datastore datastore.Datastore) Manager {
	return &managerImpl{
		datastore: datastore,
		dedupers:  make(map[string]Deduper),
	}
}

type managerImpl struct {
	datastore datastore.Datastore

	dedupersLock sync.RWMutex
	dedupers     map[string]Deduper
}

func (m *managerImpl) flushHashes(ctx context.Context) {
	var hashesToFlush []*storage.Hash
	concurrency.WithLock(&m.dedupersLock, func() {
		hashesToFlush = make([]*storage.Hash, 0, len(m.dedupers))
		for clusterID, deduper := range m.dedupers {
			hashesToFlush = append(hashesToFlush, &storage.Hash{
				ClusterId: clusterID,
				Hashes:    deduper.GetSuccessfulHashes(),
			})
		}
	})
	if err := m.datastore.UpsertHashes(ctx, hashesToFlush); err != nil {
		log.Errorf("flushing hashes: %v", err)
	}
}

func (m *managerImpl) Start(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.flushHashes(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (m *managerImpl) getDeduper(clusterID string) (Deduper, bool) {
	m.dedupersLock.RLock()
	defer m.dedupersLock.RUnlock()

	d, ok := m.dedupers[clusterID]
	return d, ok
}

func (m *managerImpl) GetDeduper(ctx context.Context, clusterID string) Deduper {
	d, ok := m.getDeduper(clusterID)
	if ok {
		return d
	}
	hash, exists, err := m.datastore.GetHashes(ctx, clusterID)
	if err != nil {
		log.Errorf("could not get hashes from database for cluster %q: %v", clusterID, err)
	}
	if !exists {
		d = NewDeduper(make(map[string]uint64))
	} else {
		d = NewDeduper(hash.GetHashes())
	}
	concurrency.WithLock(&m.dedupersLock, func() {
		m.dedupers[clusterID] = d
	})
	return d
}

func (m *managerImpl) Delete(ctx context.Context, clusterID string) error {
	concurrency.WithLock(&m.dedupersLock, func() {
		delete(m.dedupers, clusterID)
	})

	return m.datastore.DeleteHashes(ctx, clusterID)
}
