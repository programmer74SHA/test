package app

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	AssetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	UserPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gorm.io/gorm"
)

type AppContainer interface {
	AssetService() AssetPort.Service
	UserService(ctx context.Context) UserPort.Service
	Config() config.Config
	DB() *gorm.DB
}
