package service

import (
	"context"
	"regexp"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/config/datastore"
	"github.com/stackrox/rox/central/convert/storagetov1"
	"github.com/stackrox/rox/central/convert/v1tostorage"
	"github.com/stackrox/rox/central/platform/matcher"
	"github.com/stackrox/rox/central/platform/reprocessor"
	"github.com/stackrox/rox/central/telemetry/centralclient"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/auth/permissions"
	"github.com/stackrox/rox/pkg/errox"
	"github.com/stackrox/rox/pkg/features"
	pkgGRPC "github.com/stackrox/rox/pkg/grpc"
	"github.com/stackrox/rox/pkg/grpc/authz"
	"github.com/stackrox/rox/pkg/grpc/authz/allow"
	"github.com/stackrox/rox/pkg/grpc/authz/or"
	"github.com/stackrox/rox/pkg/grpc/authz/perrpc"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/set"
	"google.golang.org/grpc"
)

var (
	authorizer = perrpc.FromMap(map[authz.Authorizer][]string{
		allow.Anonymous(): {
			// The GetPublicConfig endpoint is used in code flows where
			// the user is not authenticated yet. For instance the public
			// config contains banners that are rendered on the login page.
			// This endpoint should therefore remain public.
			v1.ConfigService_GetPublicConfig_FullMethodName,
		},
		or.Or(
			user.With(permissions.View(resources.VulnerabilityManagementRequests)),
			user.With(permissions.View(resources.Administration))): {
			v1.ConfigService_GetVulnerabilityExceptionConfig_FullMethodName,
		},
		user.With(permissions.View(resources.Administration)): {
			v1.ConfigService_GetConfig_FullMethodName,
			v1.ConfigService_GetPrivateConfig_FullMethodName,
			v1.ConfigService_GetPlatformComponentConfig_FullMethodName,
			v1.ConfigService_GetDefaultRedHatLayeredProductsRegex_FullMethodName,
		},
		user.With(permissions.Modify(resources.Administration)): {
			v1.ConfigService_PutConfig_FullMethodName,
			v1.ConfigService_UpdateVulnerabilityExceptionConfig_FullMethodName,
			v1.ConfigService_UpdatePlatformComponentConfig_FullMethodName,
		},
	})
)

// Service provides the interface to modify Central config
type Service interface {
	pkgGRPC.APIService

	AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error)

	v1.ConfigServiceServer
}

// New returns a new Service instance using the given DataStore.
func New(datastore datastore.DataStore) Service {
	return &serviceImpl{
		datastore: datastore,
	}
}

type serviceImpl struct {
	v1.UnimplementedConfigServiceServer

	datastore datastore.DataStore
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterConfigServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterConfigServiceHandler(ctx, mux, conn)
}

// AuthFuncOverride specifies the auth criteria for this API.
func (s *serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, authorizer.Authorized(ctx, fullMethodName)
}

// GetPublicConfig returns the publicly available config
func (s *serviceImpl) GetPublicConfig(_ context.Context, _ *v1.Empty) (*storage.PublicConfig, error) {
	publicConfig, err := s.datastore.GetPublicConfig()
	if err != nil {
		return nil, err
	}
	if publicConfig == nil {
		return &storage.PublicConfig{}, nil
	}
	return publicConfig, nil
}

// GetPrivateConfig returns the privately available config
func (s *serviceImpl) GetPrivateConfig(ctx context.Context, _ *v1.Empty) (*storage.PrivateConfig, error) {
	privateConfig, err := s.datastore.GetPrivateConfig(ctx)
	if err != nil {
		return nil, err
	}
	if privateConfig == nil {
		return &storage.PrivateConfig{}, nil
	}
	return privateConfig, nil
}

// GetConfig returns Central's config
func (s *serviceImpl) GetConfig(ctx context.Context, _ *v1.Empty) (*storage.Config, error) {
	config, err := s.datastore.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return &storage.Config{}, nil
	}
	return config, nil
}

// PutConfig updates Central's config
func (s *serviceImpl) PutConfig(ctx context.Context, req *v1.PutConfigRequest) (*storage.Config, error) {
	if req.GetConfig() == nil {
		return nil, errors.Wrap(errox.InvalidArgs, "config must be specified")
	}
	if req.GetConfig().GetPrivateConfig() == nil {
		return nil, errors.Wrap(errox.InvalidArgs, "private config must be specified")
	}
	if req.GetConfig().GetPublicConfig() == nil {
		return nil, errors.Wrap(errox.InvalidArgs, "public config must be specified")
	}

	if features.UnifiedCVEDeferral.Enabled() {
		if err := validateExceptionConfigReq(req.GetConfig().GetPrivateConfig().GetVulnerabilityExceptionConfig()); err != nil {
			return nil, err
		}
	}

	regexes := make([]*regexp.Regexp, 0)
	if platformConfig := req.GetConfig().GetPlatformComponentConfig(); platformConfig != nil {
		for _, rule := range platformConfig.GetRules() {
			if len(rule.GetNamespaceRule().GetRegex()) == 0 || len(rule.GetName()) == 0 {
				return nil, errors.New("invalid regex for rule " + rule.GetName() + " in platform component config")
			}
			regex, compileErr := regexp.Compile(rule.GetNamespaceRule().GetRegex())
			if compileErr != nil {
				return nil, compileErr
			}
			regexes = append(regexes, regex)
		}
	}
	if err := s.datastore.UpsertConfig(ctx, req.GetConfig()); err != nil {
		return nil, err
	}
	if req.GetConfig().GetPublicConfig().GetTelemetry().GetEnabled() {
		centralclient.Enable()
	} else {
		centralclient.Disable()
	}
	matcher.Singleton().SetRegexes(regexes)
	go reprocessor.Singleton().RunReprocessor()
	return req.GetConfig(), nil
}

// GetVulnerabilityExceptionConfig returns Central's vulnerability exception configuration.
func (s *serviceImpl) GetVulnerabilityExceptionConfig(ctx context.Context, _ *v1.Empty) (*v1.GetVulnerabilityExceptionConfigResponse, error) {
	if !features.UnifiedCVEDeferral.Enabled() {
		return nil, errors.Errorf("Cannot fulfill request. Environment variable %s=false", features.UnifiedCVEDeferral.EnvVar())
	}
	vmExceptionConfig, err := s.datastore.GetVulnerabilityExceptionConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.GetVulnerabilityExceptionConfigResponse{
		Config: storagetov1.VulnerabilityExceptionConfig(vmExceptionConfig),
	}, nil
}

// UpdateVulnerabilityExceptionConfig updates Central's vulnerability exception configuration.
func (s *serviceImpl) UpdateVulnerabilityExceptionConfig(ctx context.Context, req *v1.UpdateVulnerabilityExceptionConfigRequest) (*v1.UpdateVulnerabilityExceptionConfigResponse, error) {
	if !features.UnifiedCVEDeferral.Enabled() {
		return nil, errors.Errorf("Cannot fulfill request. Environment variable %s=false", features.UnifiedCVEDeferral.EnvVar())
	}
	if req == nil {
		return nil, errors.Wrap(errox.InvalidArgs, "request cannot be nil")
	}
	exceptionCfg := v1tostorage.VulnerabilityExceptionConfig(req.GetConfig())
	if err := validateExceptionConfigReq(exceptionCfg); err != nil {
		return nil, err
	}

	config, err := s.datastore.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &storage.Config{}
	}
	if config.GetPrivateConfig() == nil {
		config.PrivateConfig = &storage.PrivateConfig{}
	}

	config.PrivateConfig.VulnerabilityExceptionConfig = exceptionCfg
	if err := s.datastore.UpsertConfig(ctx, config); err != nil {
		return nil, err
	}

	return &v1.UpdateVulnerabilityExceptionConfigResponse{
		Config: req.GetConfig(),
	}, nil
}

func (s *serviceImpl) GetPlatformComponentConfig(ctx context.Context, _ *v1.Empty) (*storage.PlatformComponentConfig, error) {
	if !features.CustomizablePlatformComponents.Enabled() {
		return nil, errors.Errorf("Cannot fulfill request. Environment variable %s=false", features.CustomizablePlatformComponents.EnvVar())
	}
	config, found, err := s.datastore.GetPlatformComponentConfig(ctx)
	if !found || err != nil {
		return nil, err
	}
	return config, nil
}

func (s *serviceImpl) UpdatePlatformComponentConfig(ctx context.Context, req *v1.PutPlatformComponentConfigRequest) (*storage.PlatformComponentConfig, error) {
	if !features.CustomizablePlatformComponents.Enabled() {
		return nil, errors.Errorf("Cannot fulfill request. Environment variable %s=false", features.CustomizablePlatformComponents.EnvVar())
	}
	regexes := make([]*regexp.Regexp, 0)
	for _, rule := range req.GetRules() {
		if len(rule.GetNamespaceRule().GetRegex()) == 0 || len(rule.GetName()) == 0 {
			return nil, errors.New("invalid regex for rule " + rule.GetName() + " in platform component config")
		}
		regex, compileErr := regexp.Compile(rule.GetNamespaceRule().GetRegex())
		if compileErr != nil {
			return nil, compileErr
		}
		regexes = append(regexes, regex)
	}
	config, err := s.datastore.UpsertPlatformComponentConfigRules(ctx, req.Rules)
	if err != nil {
		return nil, err
	}
	matcher.Singleton().SetRegexes(regexes)
	go reprocessor.Singleton().RunReprocessor()
	return config, nil
}

func (s *serviceImpl) GetDefaultRedHatLayeredProductsRegex(_ context.Context, _ *v1.Empty) (*v1.GetDefaultRedHatLayeredProductsRegexResponse, error) {
	return &v1.GetDefaultRedHatLayeredProductsRegexResponse{
		Regex: datastore.PlatformComponentLayeredProductsDefaultRegex,
	}, nil
}

func validateExceptionConfigReq(config *storage.VulnerabilityExceptionConfig) error {
	if config == nil {
		return errors.Wrap(errox.InvalidArgs, "vulnerability exception config must be specified")
	}
	expiryOptions := config.GetExpiryOptions()
	if len(expiryOptions.GetDayOptions()) == 0 {
		return errors.Wrap(errox.InvalidArgs, "number of days based vulnerability exception expiry options must be specified")
	}

	var atLeastOneEnabled bool
	seenDays := set.NewIntSet()
	for _, dayOption := range expiryOptions.GetDayOptions() {
		if !dayOption.GetEnabled() {
			continue
		}
		atLeastOneEnabled = true
		if dayOption.GetNumDays() <= 0 {
			return errors.Wrap(errox.InvalidArgs, "enabled number of days based vulnerability exception expiry option must be least one day")
		}
		if !seenDays.Add(int(dayOption.GetNumDays())) {
			return errors.Wrap(errox.InvalidArgs, "all enabled number of days based vulnerability exception expiry options must be unique")
		}
	}

	if expiryOptions.GetFixableCveOptions() == nil {
		return errors.Wrap(errox.InvalidArgs, "fixability based vulnerability exception expiry options must be specified")
	}

	atLeastOneEnabled = atLeastOneEnabled ||
		expiryOptions.GetFixableCveOptions().GetAllFixable() ||
		expiryOptions.GetFixableCveOptions().GetAnyFixable() ||
		expiryOptions.GetCustomDate() ||
		expiryOptions.GetIndefinite()
	if !atLeastOneEnabled {
		return errors.Wrap(errox.InvalidArgs, "at least one vulnerability exception expiry option must be enabled")
	}
	return nil
}
