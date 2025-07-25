package fixtures

import (
	"time"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/fixtures/fixtureconsts"
	"github.com/stackrox/rox/pkg/protoconv"
)

// GetOpenPlopObject1 Return an open plop object
func GetOpenPlopObject1() *storage.ProcessListeningOnPortFromSensor {
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           1234,
		Protocol:       storage.L4Protocol_L4_PROTOCOL_TCP,
		CloseTimestamp: nil,
		Process: &storage.ProcessIndicatorUniqueKey{
			PodId:               fixtureconsts.PodName1,
			ContainerName:       "containername",
			ProcessName:         "test_process1",
			ProcessArgs:         "test_arguments1",
			ProcessExecFilePath: "test_path1",
		},
		DeploymentId: fixtureconsts.Deployment1,
		ClusterId:    fixtureconsts.Cluster1,
		PodUid:       fixtureconsts.PodUID1,
	}
}

// GetClosePlopObject1 Return an open plop object
func GetClosePlopObject1() *storage.ProcessListeningOnPortFromSensor {
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           1234,
		Protocol:       storage.L4Protocol_L4_PROTOCOL_TCP,
		CloseTimestamp: protoconv.ConvertTimeToTimestamp(time.Now()),
		Process: &storage.ProcessIndicatorUniqueKey{
			PodId:               fixtureconsts.PodName1,
			ContainerName:       "containername",
			ProcessName:         "test_process1",
			ProcessArgs:         "test_arguments1",
			ProcessExecFilePath: "test_path1",
		},
		DeploymentId: fixtureconsts.Deployment1,
		ClusterId:    fixtureconsts.Cluster1,
		PodUid:       fixtureconsts.PodUID1,
	}
}

// GetOpenPlopObject2 Return an open plop object
func GetOpenPlopObject2() *storage.ProcessListeningOnPortFromSensor {
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           80,
		Protocol:       storage.L4Protocol_L4_PROTOCOL_TCP,
		CloseTimestamp: nil,
		Process: &storage.ProcessIndicatorUniqueKey{
			PodId:               fixtureconsts.PodName1,
			ContainerName:       "containername",
			ProcessName:         "test_process2",
			ProcessArgs:         "test_arguments2",
			ProcessExecFilePath: "test_path2",
		},
		DeploymentId: fixtureconsts.Deployment1,
		ClusterId:    fixtureconsts.Cluster1,
		PodUid:       fixtureconsts.PodUID1,
	}
}

// GetOpenPlopObject3 Return an open plop object
func GetOpenPlopObject3() *storage.ProcessListeningOnPortFromSensor {
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           80,
		Protocol:       storage.L4Protocol_L4_PROTOCOL_TCP,
		CloseTimestamp: nil,
		Process: &storage.ProcessIndicatorUniqueKey{
			PodId:               fixtureconsts.PodName2,
			ContainerName:       "containername",
			ProcessName:         "apt-get",
			ProcessArgs:         "install nmap",
			ProcessExecFilePath: "bin",
		},
		DeploymentId: fixtureconsts.Deployment1,
		ClusterId:    fixtureconsts.Cluster1,
		PodUid:       fixtureconsts.PodUID2,
	}
}

// GetOpenPlopObject4 Return an open plop object
func GetOpenPlopObject4() *storage.ProcessListeningOnPortFromSensor {
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           80,
		Protocol:       storage.L4Protocol_L4_PROTOCOL_TCP,
		CloseTimestamp: nil,
		Process: &storage.ProcessIndicatorUniqueKey{
			PodId:               fixtureconsts.PodName2,
			ContainerName:       "containername",
			ProcessName:         "apt-get",
			ProcessArgs:         "install nmap",
			ProcessExecFilePath: "bin",
		},
		DeploymentId: fixtureconsts.Deployment1,
		ClusterId:    fixtureconsts.Cluster1,
		PodUid:       fixtureconsts.PodUID3,
	}
}

// GetPlopStorage1 Return a plop for the database
func GetPlopStorage1() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID1,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID1,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment6,
	}
}

// GetPlopStorage2 Return a plop for the database
func GetPlopStorage2() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID2,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID2,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment5,
	}
}

// GetPlopStorage3 Return a plop for the database
func GetPlopStorage3() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID3,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID3,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment3,
	}
}

// GetPlopStorage4 Return a plop for the database
// It is the same as GetPlopStorage1 except it has a PodUid
func GetPlopStorage4() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID4,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID1,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment6,
		PodUid:             fixtureconsts.PodUID1,
	}
}

// GetPlopStorage5 Return a plop for the database
// It is the same as GetPlopStorage2 except it has a PodUid
func GetPlopStorage5() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID5,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID2,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment5,
		PodUid:             fixtureconsts.PodUID2,
	}
}

// GetPlopStorage6 Return a plop for the database
// It is the same as GetPlopStorage3 except it has a PodUid
func GetPlopStorage6() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID6,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID3,
		CloseTimestamp:     protoconv.NowMinus(20 * time.Minute),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment3,
		PodUid:             fixtureconsts.PodUID3,
	}
}

// GetPlopStorage7 Return a plop for the database
func GetPlopStorage7() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID1,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID1,
		CloseTimestamp:     nil,
		Closed:             false,
		DeploymentId:       fixtureconsts.Deployment1,
		PodUid:             fixtureconsts.PodUID1,
	}
}

// GetPlopStorage8 Return a plop for the database
func GetPlopStorage8() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID2,
		Port:               4321,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID2,
		CloseTimestamp:     nil,
		Closed:             false,
		DeploymentId:       fixtureconsts.Deployment1,
		PodUid:             fixtureconsts.PodUID3,
	}
}

// GetPlopStorage9 Return a plop for the database
func GetPlopStorage9() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID3,
		Port:               80,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID3,
		CloseTimestamp:     nil,
		Closed:             false,
		DeploymentId:       fixtureconsts.Deployment1,
		PodUid:             fixtureconsts.PodUID3,
	}
}

func GetPlop7() *storage.ProcessListeningOnPort {
	return &storage.ProcessListeningOnPort{
		ContainerName: "test_container1",
		PodId:         fixtureconsts.PodName1,
		PodUid:        fixtureconsts.PodUID1,
		DeploymentId:  fixtureconsts.Deployment1,
		ClusterId:     fixtureconsts.Cluster1,
		Namespace:     fixtureconsts.Namespace1,
		Endpoint: &storage.ProcessListeningOnPort_Endpoint{
			Port:     1234,
			Protocol: storage.L4Protocol_L4_PROTOCOL_TCP,
		},
		Signal: &storage.ProcessSignal{
			Name:         "test_process1",
			Args:         "test_arguments1",
			ExecFilePath: "test_path1",
		},
	}
}

func GetPlop8() *storage.ProcessListeningOnPort {
	return &storage.ProcessListeningOnPort{
		ContainerName: "test_container2",
		PodId:         fixtureconsts.PodName3,
		PodUid:        fixtureconsts.PodUID3,
		DeploymentId:  fixtureconsts.Deployment1,
		ClusterId:     fixtureconsts.Cluster1,
		Namespace:     fixtureconsts.Namespace1,
		Endpoint: &storage.ProcessListeningOnPort_Endpoint{
			Port:     4321,
			Protocol: storage.L4Protocol_L4_PROTOCOL_TCP,
		},
		Signal: &storage.ProcessSignal{
			Name:         "test_process2",
			Args:         "test_arguments2",
			ExecFilePath: "test_path2",
		},
	}
}

func GetPlop9() *storage.ProcessListeningOnPort {
	return &storage.ProcessListeningOnPort{
		ContainerName: "test_container2",
		PodId:         fixtureconsts.PodName3,
		PodUid:        fixtureconsts.PodUID3,
		DeploymentId:  fixtureconsts.Deployment1,
		ClusterId:     fixtureconsts.Cluster1,
		Namespace:     fixtureconsts.Namespace1,
		Endpoint: &storage.ProcessListeningOnPort_Endpoint{
			Port:     80,
			Protocol: storage.L4Protocol_L4_PROTOCOL_TCP,
		},
		Signal: &storage.ProcessSignal{
			Name:         "test_process3",
			Args:         "test_arguments3",
			ExecFilePath: "test_path3",
		},
	}
}

// GetPlopStorageExpired1 Return an expired plop for the database
func GetPlopStorageExpired1() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID7,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID1,
		CloseTimestamp:     protoconv.NowMinus(1 * time.Hour),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment6,
		PodUid:             fixtureconsts.PodUID1,
	}
}

// GetPlopStorageExpired2 Return an expired plop for the database
func GetPlopStorageExpired2() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID8,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID2,
		CloseTimestamp:     protoconv.NowMinus(1 * time.Hour),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment5,
		PodUid:             fixtureconsts.PodUID2,
	}
}

// GetPlopStorageExpired3 Return an expired plop for the database
func GetPlopStorageExpired3() *storage.ProcessListeningOnPortStorage {
	return &storage.ProcessListeningOnPortStorage{
		Id:                 fixtureconsts.PlopUID9,
		Port:               1234,
		Protocol:           storage.L4Protocol_L4_PROTOCOL_TCP,
		ProcessIndicatorId: fixtureconsts.ProcessIndicatorID3,
		CloseTimestamp:     protoconv.NowMinus(1 * time.Hour),
		Closed:             true,
		DeploymentId:       fixtureconsts.Deployment3,
		PodUid:             fixtureconsts.PodUID3,
	}
}
