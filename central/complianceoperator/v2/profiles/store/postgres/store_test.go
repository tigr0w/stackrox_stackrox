// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stretchr/testify/suite"
)

type ComplianceOperatorProfileV2StoreSuite struct {
	suite.Suite
	store  Store
	testDB *pgtest.TestPostgres
}

func TestComplianceOperatorProfileV2Store(t *testing.T) {
	suite.Run(t, new(ComplianceOperatorProfileV2StoreSuite))
}

func (s *ComplianceOperatorProfileV2StoreSuite) SetupSuite() {

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.DB)
}

func (s *ComplianceOperatorProfileV2StoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE compliance_operator_profile_v2 CASCADE")
	s.T().Log("compliance_operator_profile_v2", tag)
	s.NoError(err)
}

func (s *ComplianceOperatorProfileV2StoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
}

func (s *ComplianceOperatorProfileV2StoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	complianceOperatorProfileV2 := &storage.ComplianceOperatorProfileV2{}
	s.NoError(testutils.FullInit(complianceOperatorProfileV2, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundComplianceOperatorProfileV2, exists, err := store.Get(ctx, complianceOperatorProfileV2.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundComplianceOperatorProfileV2)

	withNoAccessCtx := sac.WithNoAccess(ctx)

	s.NoError(store.Upsert(ctx, complianceOperatorProfileV2))
	foundComplianceOperatorProfileV2, exists, err = store.Get(ctx, complianceOperatorProfileV2.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(complianceOperatorProfileV2, foundComplianceOperatorProfileV2)

	complianceOperatorProfileV2Count, err := store.Count(ctx)
	s.NoError(err)
	s.Equal(1, complianceOperatorProfileV2Count)
	complianceOperatorProfileV2Count, err = store.Count(withNoAccessCtx)
	s.NoError(err)
	s.Zero(complianceOperatorProfileV2Count)

	complianceOperatorProfileV2Exists, err := store.Exists(ctx, complianceOperatorProfileV2.GetId())
	s.NoError(err)
	s.True(complianceOperatorProfileV2Exists)
	s.NoError(store.Upsert(ctx, complianceOperatorProfileV2))
	s.ErrorIs(store.Upsert(withNoAccessCtx, complianceOperatorProfileV2), sac.ErrResourceAccessDenied)

	foundComplianceOperatorProfileV2, exists, err = store.Get(ctx, complianceOperatorProfileV2.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(complianceOperatorProfileV2, foundComplianceOperatorProfileV2)

	s.NoError(store.Delete(ctx, complianceOperatorProfileV2.GetId()))
	foundComplianceOperatorProfileV2, exists, err = store.Get(ctx, complianceOperatorProfileV2.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundComplianceOperatorProfileV2)
	s.ErrorIs(store.Delete(withNoAccessCtx, complianceOperatorProfileV2.GetId()), sac.ErrResourceAccessDenied)

	var complianceOperatorProfileV2s []*storage.ComplianceOperatorProfileV2
	var complianceOperatorProfileV2IDs []string
	for i := 0; i < 200; i++ {
		complianceOperatorProfileV2 := &storage.ComplianceOperatorProfileV2{}
		s.NoError(testutils.FullInit(complianceOperatorProfileV2, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		complianceOperatorProfileV2s = append(complianceOperatorProfileV2s, complianceOperatorProfileV2)
		complianceOperatorProfileV2IDs = append(complianceOperatorProfileV2IDs, complianceOperatorProfileV2.GetId())
	}

	s.NoError(store.UpsertMany(ctx, complianceOperatorProfileV2s))
	allComplianceOperatorProfileV2, err := store.GetAll(ctx)
	s.NoError(err)
	s.ElementsMatch(complianceOperatorProfileV2s, allComplianceOperatorProfileV2)

	complianceOperatorProfileV2Count, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(200, complianceOperatorProfileV2Count)

	s.NoError(store.DeleteMany(ctx, complianceOperatorProfileV2IDs))

	complianceOperatorProfileV2Count, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(0, complianceOperatorProfileV2Count)
}