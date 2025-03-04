package connection

import (
	"context"
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	clusterMgrMock "github.com/stackrox/rox/central/sensor/service/common/mocks"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy/policyversion"
	"github.com/stackrox/rox/pkg/centralsensor"
	"github.com/stackrox/rox/pkg/concurrency"
	testutilsMTLS "github.com/stackrox/rox/pkg/mtls/testutils"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
)

func TestHandler(t *testing.T) {
	suite.Run(t, new(testSuite))
}

type testSuite struct {
	suite.Suite
}

func (s *testSuite) SetupTest() {
	err := testutilsMTLS.LoadTestMTLSCerts(s.T())
	s.Require().NoError(err)
}

type mockServer struct {
	grpc.ServerStream
	sentList []*central.MsgToSensor
}

func (c *mockServer) Send(msg *central.MsgToSensor) error {
	c.sentList = append(c.sentList, msg)
	return nil
}

func (c *mockServer) Recv() (*central.MsgFromSensor, error) {
	return nil, nil
}

func (s *testSuite) TestGetPolicySyncMsgFromPoliciesDoesntDowngradeBelowMinimumVersion() {
	sensorMockConn := &sensorConnection{
		sensorHello: &central.SensorHello{
			PolicyVersion: "1",
		},
	}

	msg, err := sensorMockConn.getPolicySyncMsgFromPolicies([]*storage.Policy{{PolicyVersion: policyversion.CurrentVersion().String()}})
	s.NoError(err)

	policySync := msg.GetPolicySync()
	s.Require().NotNil(policySync)
	s.NotEmpty(policySync.Policies)
	s.Equal(policyversion.CurrentVersion().String(), policySync.Policies[0].GetPolicyVersion())
}

func (s *testSuite) TestGetPolicySyncMsgFromPoliciesDoesntDowngradeInvalidVersions() {
	sensorMockConn := &sensorConnection{
		sensorHello: &central.SensorHello{
			PolicyVersion: "this ain't a version",
		},
	}

	msg, err := sensorMockConn.getPolicySyncMsgFromPolicies([]*storage.Policy{{PolicyVersion: policyversion.CurrentVersion().String()}})
	s.NoError(err)

	policySync := msg.GetPolicySync()
	s.Require().NotNil(policySync)
	s.NotEmpty(policySync.Policies)
	s.Equal(policyversion.CurrentVersion().String(), policySync.Policies[0].GetPolicyVersion())
}

func (s *testSuite) TestSendsAuditLogSyncMessageIfEnabledOnRun() {
	ctx := context.Background()
	clusterID := "this-cluster"
	auditLogState := map[string]*storage.AuditLogFileState{
		"node-a": {
			CollectLogsSince: types.TimestampNow(),
			LastAuditId:      "abcd",
		},
	}
	cluster := &storage.Cluster{
		Id:            clusterID,
		DynamicConfig: &storage.DynamicClusterConfig{},
		AuditLogState: auditLogState,
	}

	ctrl := gomock.NewController(s.T())
	mgrMock := clusterMgrMock.NewMockClusterManager(ctrl)

	sensorMockConn := &sensorConnection{
		clusterID:  clusterID,
		clusterMgr: mgrMock,
	}
	server := &mockServer{
		sentList: make([]*central.MsgToSensor, 0),
	}
	caps := set.NewSet(centralsensor.AuditLogEventsCap)

	mgrMock.EXPECT().GetCluster(ctx, clusterID).Return(cluster, true, nil).AnyTimes()

	s.NoError(sensorMockConn.Run(ctx, server, caps))

	for _, msg := range server.sentList {
		if syncMsg := msg.GetAuditLogSync(); syncMsg != nil {
			s.Equal(auditLogState, syncMsg.GetNodeAuditLogFileStates())
			return
		}
	}

	s.FailNow("Audit log sync message was not sent")
}

func (s *testSuite) TestIssueLocalScannerCerts() {
	namespace, clusterID, requestID := "namespace", "clusterID", "requestID"
	testCases := map[string]struct {
		requestID  string
		namespace  string
		clusterID  string
		shouldFail bool
	}{
		"no parameter missing": {requestID: requestID, namespace: namespace, clusterID: clusterID, shouldFail: false},
		"requestID missing":    {requestID: "", namespace: namespace, clusterID: clusterID, shouldFail: true},
		"namespace missing":    {requestID: requestID, namespace: "", clusterID: clusterID, shouldFail: true},
		"clusterID missing":    {requestID: requestID, namespace: namespace, clusterID: "", shouldFail: true},
	}
	for tcName, tc := range testCases {
		s.Run(tcName, func() {
			sendC := make(chan *central.MsgToSensor)
			sensorMockConn := &sensorConnection{
				clusterID: tc.clusterID,
				sendC:     sendC,
				stopSig:   concurrency.NewErrorSignal(),
				sensorHello: &central.SensorHello{
					DeploymentIdentification: &storage.SensorDeploymentIdentification{
						AppNamespace: tc.namespace,
					},
				},
			}
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
			defer cancel()
			request := &central.MsgFromSensor{
				Msg: &central.MsgFromSensor_IssueLocalScannerCertsRequest{
					IssueLocalScannerCertsRequest: &central.IssueLocalScannerCertsRequest{
						RequestId: tc.requestID,
					},
				},
			}

			handleDoneErrSig := concurrency.NewErrorSignal()
			go func() {
				handleDoneErrSig.SignalWithError(sensorMockConn.handleMessage(ctx, request))
			}()

			select {
			case msgToSensor := <-sendC:
				response := msgToSensor.GetIssueLocalScannerCertsResponse()
				s.Equal(tc.requestID, response.GetRequestId())
				if tc.shouldFail {
					s.NotNil(response.GetError())
				} else {
					s.NotNil(response.GetCertificates())
				}
			case <-ctx.Done():
				s.Fail(ctx.Err().Error())
			}

			handleErr, ok := handleDoneErrSig.WaitUntil(ctx)
			s.Require().True(ok)
			s.NoError(handleErr)
		})
	}
}

func (s *testSuite) TestDelegatedRegistryConfigOnRun() {
	ctx := context.Background()
	clusterID := "this-cluster"
	cluster := &storage.Cluster{
		Id: clusterID,
	}

	ctrl := gomock.NewController(s.T())
	mgrMock := clusterMgrMock.NewMockClusterManager(ctrl)
	deleRegMgr := clusterMgrMock.NewMockDelegatedRegistryConfigManager(ctrl)

	sensorMockConn := &sensorConnection{
		clusterID:                  clusterID,
		clusterMgr:                 mgrMock,
		delegatedRegistryConfigMgr: deleRegMgr,
	}
	mgrMock.EXPECT().GetCluster(ctx, clusterID).Return(cluster, true, nil).AnyTimes()

	s.Run("send", func() {
		caps := set.NewSet(centralsensor.DelegatedRegistryCap)

		config := &storage.DelegatedRegistryConfig{EnabledFor: storage.DelegatedRegistryConfig_ALL}
		deleRegMgr.EXPECT().GetConfig(ctx).Return(config, true, nil)

		server := &mockServer{sentList: make([]*central.MsgToSensor, 0)}
		s.NoError(sensorMockConn.Run(ctx, server, caps))

		for _, msg := range server.sentList {
			if deleConfig := msg.GetDelegatedRegistryConfig(); deleConfig != nil {
				s.Equal(central.DelegatedRegistryConfig_ALL, deleConfig.EnabledFor)
				return
			}
		}

		s.FailNow("Delegated registry config msg was not sent")
	})

	s.Run("no send on no cap", func() {
		caps := set.NewSet[centralsensor.SensorCapability]()

		server := &mockServer{sentList: make([]*central.MsgToSensor, 0)}
		s.NoError(sensorMockConn.Run(ctx, server, caps))

		for _, msg := range server.sentList {
			if deleConfig := msg.GetDelegatedRegistryConfig(); deleConfig != nil {
				s.FailNow("Delegated registry config msg was sent")
				return
			}
		}
	})

	s.Run("no send on nil config", func() {
		caps := set.NewSet(centralsensor.DelegatedRegistryCap)

		deleRegMgr.EXPECT().GetConfig(ctx).Return(nil, false, nil)

		server := &mockServer{sentList: make([]*central.MsgToSensor, 0)}
		s.NoError(sensorMockConn.Run(ctx, server, caps))

		for _, msg := range server.sentList {
			if deleConfig := msg.GetDelegatedRegistryConfig(); deleConfig != nil {
				s.FailNow("Delegated registry config msg was sent")
				return
			}
		}
	})

	s.Run("no send on err", func() {
		caps := set.NewSet(centralsensor.DelegatedRegistryCap)

		deleRegMgr.EXPECT().GetConfig(ctx).Return(nil, false, errors.New("fake error"))

		server := &mockServer{sentList: make([]*central.MsgToSensor, 0)}
		err := sensorMockConn.Run(ctx, server, caps)
		s.ErrorContains(err, "unable to get delegated registry config")
	})
}
