package datastore

import (
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/globalindex"
	"github.com/stackrox/rox/central/reportconfigurations/index"
	"github.com/stackrox/rox/central/reportconfigurations/search"
	"github.com/stackrox/rox/central/reportconfigurations/store"
	pgStore "github.com/stackrox/rox/central/reportconfigurations/store/postgres"
	reportConfigStore "github.com/stackrox/rox/central/reportconfigurations/store/rocksdb"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	once sync.Once
	ds   DataStore
)

// Singleton creates a singleton for the report configuration datastore and loads the plugin client config
func Singleton() DataStore {
	once.Do(func() {
		var err error
		var storage store.Store
		var indexer index.Indexer
		if env.PostgresDatastoreEnabled.BooleanSetting() {
			storage = pgStore.New(globaldb.GetPostgres())
			indexer = pgStore.NewIndexer(globaldb.GetPostgres())
		} else {
			storage, err = reportConfigStore.New(globaldb.GetRocksDB())
			indexer = index.New(globalindex.GetGlobalTmpIndex())
			utils.CrashOnError(err)
		}

		ds, err = New(storage, indexer, search.New(storage, indexer))
		if err != nil {
			log.Panicf("Failed to initialize report configurations datastore: %s", err)
		}
	})
	return ds
}
