package http

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

// user service transient instance handler
func userServiceGetter(appContainer app.AppContainer, cfg config.ServerConfig) ServiceGetter[*service.UserService] {
	return func(ctx context.Context) *service.UserService {
		return service.NewUserService(appContainer.UserService(ctx), cfg.Secret, cfg.AuthExpMinute, cfg.AuthRefreshMinute)
	}
}

// scanner service transient instance handler
func scannerServiceGetter(appContainer app.AppContainer) ServiceGetter[*service.ScannerService] {
	return func(ctx context.Context) *service.ScannerService {
		// Get the API scanner service directly from the app container
		if apiScannerService := appContainer.GetAPIScannerService(); apiScannerService != nil {
			return apiScannerService
		}

		// Fallback to creating a new service
		return service.NewScannerService(appContainer.ScannerService(ctx))
	}
}

// asset service transient instance handler
func assetServiceGetter(appContainer app.AppContainer) ServiceGetter[*service.AssetService] {
	return func(ctx context.Context) *service.AssetService {
		return service.NewAssetService(appContainer.AssetService(ctx))
	}
}

// scan job service transient instance handler
func scanJobServiceGetter(appContainer app.AppContainer) ServiceGetter[*service.ScanJobService] {
	return func(ctx context.Context) *service.ScanJobService {
		return service.NewScanJobService(appContainer.ScanJobService(ctx))
	}
}
