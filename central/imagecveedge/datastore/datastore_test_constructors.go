package datastore

import (
	"testing"

	"github.com/blevesearch/bleve"
	clusterIndex "github.com/stackrox/rox/central/cluster/index"
	componentCVEEdgeIndex "github.com/stackrox/rox/central/componentcveedge/index"
	"github.com/stackrox/rox/central/cve/index"
	deploymentIndex "github.com/stackrox/rox/central/deployment/index"
	imageIndex "github.com/stackrox/rox/central/image/index"
	componentIndex "github.com/stackrox/rox/central/imagecomponent/index"
	imageComponentEdgeIndex "github.com/stackrox/rox/central/imagecomponentedge/index"
	pgStore "github.com/stackrox/rox/central/imagecveedge/datastore/postgres"
	imageCVEEdgeIndex "github.com/stackrox/rox/central/imagecveedge/index"
	"github.com/stackrox/rox/central/imagecveedge/search"
	dackboxStore "github.com/stackrox/rox/central/imagecveedge/store/dackbox"
	"github.com/stackrox/rox/pkg/dackbox"
	"github.com/stackrox/rox/pkg/dackbox/concurrency"
	"github.com/stackrox/rox/pkg/postgres"
)

// GetTestRocksBleveDataStore provides a datastore connected to rocksdb and bleve for testing purposes.
func GetTestRocksBleveDataStore(_ *testing.T, bleveIndex bleve.Index, dacky *dackbox.DackBox, keyFence concurrency.KeyFence) DataStore {
	return New(
		dacky,
		dackboxStore.New(dacky, keyFence),
		search.New(dackboxStore.New(dacky, keyFence),
			index.New(bleveIndex),
			imageCVEEdgeIndex.New(bleveIndex),
			componentCVEEdgeIndex.New(bleveIndex),
			componentIndex.New(bleveIndex),
			imageComponentEdgeIndex.New(bleveIndex),
			imageIndex.New(bleveIndex),
			deploymentIndex.New(bleveIndex, bleveIndex),
			clusterIndex.New(bleveIndex),
		))
}

// GetTestPostgresDataStore provides a datastore connected to postgres for testing purposes.
func GetTestPostgresDataStore(_ *testing.T, pool postgres.DB) DataStore {
	return New(
		nil,
		pgStore.New(pool),
		search.NewV2(pgStore.New(pool),
			pgStore.NewIndexer(pool),
		),
	)
}
