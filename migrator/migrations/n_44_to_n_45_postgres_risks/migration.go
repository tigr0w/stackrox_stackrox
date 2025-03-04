// Code generated by pg-bindings generator. DO NOT EDIT.
package n44ton45

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_44_to_n_45_postgres_risks/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_44_to_n_45_postgres_risks/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 44 // 155

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 156
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving risks from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = frozenSchema.RisksSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB postgres.DB, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableRisksStmt)
	var risks []*storage.Risk
	err := walk(ctx, legacyStore, func(obj *storage.Risk) error {
		risks = append(risks, obj)
		if len(risks) == batchSize {
			if err := store.UpsertMany(ctx, risks); err != nil {
				log.WriteToStderrf("failed to persist risks to store %v", err)
				return err
			}
			risks = risks[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(risks) > 0 {
		if err = store.UpsertMany(ctx, risks); err != nil {
			log.WriteToStderrf("failed to persist risks to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.Risk) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
