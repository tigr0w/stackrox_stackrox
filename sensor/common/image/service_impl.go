package image

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/internalapi/sensor"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/expiringcache"
	grpcPkg "github.com/stackrox/rox/pkg/grpc"
	"github.com/stackrox/rox/pkg/grpc/authz/idcheck"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/sensor/common/imagecacheutils"
	"github.com/stackrox/rox/sensor/common/registry"
	"github.com/stackrox/rox/sensor/common/scan"
	"google.golang.org/grpc"
)

var (
	log = logging.LoggerForModule()
)

// Service is an interface to receiving image scan results for the Admission Controller.
type Service interface {
	grpcPkg.APIService
	sensor.ImageServiceServer
	AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error)

	SetClient(conn grpc.ClientConnInterface)
}

// NewService returns the ImageService API for the Admission Controller to use.
func NewService(imageCache expiringcache.Cache, registryStore *registry.Store) Service {
	return &serviceImpl{
		imageCache:    imageCache,
		registryStore: registryStore,
		localScan:     scan.NewLocalScan(registryStore),
	}
}

type serviceImpl struct {
	sensor.UnimplementedImageServiceServer

	centralClient v1.ImageServiceClient
	imageCache    expiringcache.Cache
	registryStore *registry.Store
	localScan     *scan.LocalScan
}

func (s *serviceImpl) SetClient(conn grpc.ClientConnInterface) {
	s.centralClient = v1.NewImageServiceClient(conn)
}

func (s *serviceImpl) GetImage(ctx context.Context, req *sensor.GetImageRequest) (*sensor.GetImageResponse, error) {
	if id := req.GetImage().GetId(); id != "" {
		img, _ := s.imageCache.Get(imagecacheutils.GetImageCacheKey(req.GetImage())).(*storage.Image)
		if img != nil && (!req.GetScanInline() || img.GetScan() != nil) {
			return &sensor.GetImageResponse{
				Image: img,
			}, nil
		}
	}

	log.Debugf("scan request from admission control: %+v", req)

	// Note: The Admission Controller does NOT know if the image is cluster-local,
	// so we determine it here.
	// If Sensor's registry store has an entry for the given image's registry,
	// it is considered cluster-local.
	// This is used to determine that an image is from an OCP internal registry and
	// should not be sent to central for scanning
	req.Image.IsClusterLocal = s.registryStore.IsLocal(req.GetImage().GetName())

	// Ask Central to scan the image if the image is neither internal nor local
	if !req.GetImage().GetIsClusterLocal() {
		scanResp, err := s.centralClient.ScanImageInternal(ctx, &v1.ScanImageInternalRequest{
			Image:      req.GetImage(),
			CachedOnly: !req.GetScanInline(),
		})
		if err != nil {
			return nil, errors.Wrap(err, "scanning image via central")
		}
		return &sensor.GetImageResponse{
			Image: scanResp.GetImage(),
		}, nil
	}

	img, err := s.localScan.EnrichLocalImageInNamespace(ctx, s.centralClient, req.GetImage(), req.GetNamespace(), "", false)
	if err != nil {
		err = errors.Wrap(err, "scanning image via local scanner")
		log.Error(err)
		return nil, err
	}

	return &sensor.GetImageResponse{
		Image: img,
	}, nil
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	sensor.RegisterImageServiceServer(grpcServer, s)
}

// RegisterServiceHandler implements the APIService interface, but the agent does not accept calls over the gRPC gateway
func (s *serviceImpl) RegisterServiceHandler(context.Context, *runtime.ServeMux, *grpc.ClientConn) error {
	return nil
}

// AuthFuncOverride specifies the auth criteria for this API.
func (s *serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, idcheck.AdmissionControlOnly().Authorized(ctx, fullMethodName)
}
