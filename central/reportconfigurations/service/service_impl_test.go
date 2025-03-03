package service

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	notifierMocks "github.com/stackrox/rox/central/notifier/datastore/mocks"
	"github.com/stackrox/rox/central/reportconfigurations/datastore/mocks"
	managerMocks "github.com/stackrox/rox/central/reports/manager/mocks"
	accessScopeMocks "github.com/stackrox/rox/central/role/datastore/mocks"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stretchr/testify/suite"
)

func TestReportConfigurationService(t *testing.T) {
	suite.Run(t, new(TestReportConfigurationServiceTestSuite))
}

type TestReportConfigurationServiceTestSuite struct {
	suite.Suite
	service               Service
	reportConfigDatastore *mocks.MockDataStore
	notifierDatastore     *notifierMocks.MockDataStore
	accessScopeStore      *accessScopeMocks.MockDataStore
	manager               *managerMocks.MockManager
	mockCtrl              *gomock.Controller
}

func (s *TestReportConfigurationServiceTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	if env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip test when postgres is enabled")
		s.T().SkipNow()
	}
	s.reportConfigDatastore = mocks.NewMockDataStore(s.mockCtrl)
	s.notifierDatastore = notifierMocks.NewMockDataStore(s.mockCtrl)
	s.accessScopeStore = accessScopeMocks.NewMockDataStore(s.mockCtrl)
	s.manager = managerMocks.NewMockManager(s.mockCtrl)
	s.service = New(s.reportConfigDatastore, s.notifierDatastore, s.accessScopeStore, nil, s.manager)
}

func (s *TestReportConfigurationServiceTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func (s *TestReportConfigurationServiceTestSuite) TestAddValidReportConfiguration() {
	ctx := context.Background()

	reportConfig := fixtures.GetValidReportConfiguration()
	s.reportConfigDatastore.EXPECT().AddReportConfiguration(ctx, reportConfig).Return(reportConfig.GetId(), nil)
	s.reportConfigDatastore.EXPECT().GetReportConfiguration(ctx, reportConfig.GetId()).Return(reportConfig, true, nil)

	s.notifierDatastore.EXPECT().Exists(ctx, gomock.Any()).Return(true, nil).AnyTimes()
	s.accessScopeStore.EXPECT().AccessScopeExists(ctx, gomock.Any()).Return(true, nil).AnyTimes()

	s.manager.EXPECT().Upsert(ctx, reportConfig).Return(nil)
	_, err := s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: reportConfig,
	})
	s.NoError(err)
}

func (s *TestReportConfigurationServiceTestSuite) TestAddInvalidValidReportConfigurations() {
	ctx := context.Background()

	s.notifierDatastore.EXPECT().Exists(ctx, gomock.Any()).Return(true, nil).AnyTimes()
	s.accessScopeStore.EXPECT().AccessScopeExists(ctx, gomock.Any()).Return(true, nil).AnyTimes()

	noNotifierReportConfig := fixtures.GetInvalidReportConfigurationNoNotifier()
	_, err := s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: noNotifierReportConfig,
	})
	s.Error(err)

	incorrectScheduleReportConfig := fixtures.GetInvalidReportConfigurationIncorrectSchedule()
	_, err = s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: incorrectScheduleReportConfig,
	})
	s.Error(err)

	missingScheduleReportConfig := fixtures.GetInvalidReportConfigurationMissingSchedule()
	_, err = s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: missingScheduleReportConfig,
	})
	s.Error(err)

	missingDaysOfWeekReportConfig := fixtures.GetInvalidReportConfigurationMissingDaysOfWeek()
	_, err = s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: missingDaysOfWeekReportConfig,
	})
	s.Error(err)

	missingDaysOfMonthReportConfig := fixtures.GetInvalidReportConfigurationMissingDaysOfMonth()
	_, err = s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: missingDaysOfMonthReportConfig,
	})
	s.Error(err)

	incorrectEmailReportConfig := fixtures.GetInvalidReportConfigurationIncorrectEmail()
	_, err = s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: incorrectEmailReportConfig,
	})
	s.Error(err)
}

func (s *TestReportConfigurationServiceTestSuite) TestUpdateInvalidValidReportConfigurations() {
	ctx := context.Background()

	s.notifierDatastore.EXPECT().Exists(ctx, gomock.Any()).Return(true, nil).AnyTimes()
	s.accessScopeStore.EXPECT().AccessScopeExists(ctx, gomock.Any()).Return(true, nil).AnyTimes()

	noNotifierReportConfig := fixtures.GetInvalidReportConfigurationNoNotifier()
	_, err := s.service.UpdateReportConfiguration(ctx, &v1.UpdateReportConfigurationRequest{
		ReportConfig: noNotifierReportConfig,
	})
	s.Error(err)

	incorrectScheduleReportConfig := fixtures.GetInvalidReportConfigurationIncorrectSchedule()
	_, err = s.service.UpdateReportConfiguration(ctx, &v1.UpdateReportConfigurationRequest{
		ReportConfig: incorrectScheduleReportConfig,
	})
	s.Error(err)

	missingScheduleReportConfig := fixtures.GetInvalidReportConfigurationMissingSchedule()
	_, err = s.service.UpdateReportConfiguration(ctx, &v1.UpdateReportConfigurationRequest{
		ReportConfig: missingScheduleReportConfig,
	})
	s.Error(err)

	incorrectEmailReportConfig := fixtures.GetInvalidReportConfigurationIncorrectEmail()
	_, err = s.service.UpdateReportConfiguration(ctx, &v1.UpdateReportConfigurationRequest{
		ReportConfig: incorrectEmailReportConfig,
	})
	s.Error(err)
}

func (s *TestReportConfigurationServiceTestSuite) TestNotifierDoesNotExist() {
	ctx := context.Background()

	s.notifierDatastore.EXPECT().Exists(ctx, gomock.Any()).Return(false, nil)
	s.accessScopeStore.EXPECT().AccessScopeExists(ctx, gomock.Any()).Return(true, nil)

	reportConfig := fixtures.GetValidReportConfiguration()
	_, err := s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: reportConfig,
	})
	s.Error(err)
}

func (s *TestReportConfigurationServiceTestSuite) TestAccessScopeDoesNotExist() {
	ctx := context.Background()

	s.notifierDatastore.EXPECT().Exists(ctx, gomock.Any()).Return(true, nil).AnyTimes()
	s.accessScopeStore.EXPECT().AccessScopeExists(ctx, gomock.Any()).Return(false, nil)

	reportConfig := fixtures.GetValidReportConfiguration()
	_, err := s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: reportConfig,
	})
	s.Error(err)
}

func (s *TestReportConfigurationServiceTestSuite) TestNoMailingAddresses() {
	ctx := context.Background()
	reportConfig := fixtures.GetValidReportConfiguration()
	reportConfig.GetEmailConfig().MailingLists = []string{}

	_, err := s.service.PostReportConfiguration(ctx, &v1.PostReportConfigurationRequest{
		ReportConfig: reportConfig,
	})
	s.Error(err)
}
