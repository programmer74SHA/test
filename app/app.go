package app

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user"
	userPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/mysql"
	"gorm.io/gorm"
)

type app struct {
	db           *gorm.DB
	cfg          config.Config
	assetService assetPort.Service
	userService  userPort.Service
}

func (a *app) AssetService() assetPort.Service {
	return a.assetService
}

func (a *app) DB() *gorm.DB {
	return a.db
}

func (a *app) userServiceWithDB(db *gorm.DB) userPort.Service {
	return user.NewUserService(storage.NewUserRepo(db))
}
func (a *app) UserService(ctx context.Context) userPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.userService == nil {
			a.userService = a.userServiceWithDB(a.db)
		}
		return a.userService
	}

	return a.userServiceWithDB(db)
}

func (a *app) Config() config.Config {
	return a.cfg
}

func (a *app) setDB() error {
	db, err := mysql.NewMysqlConnection(mysql.DBConnOptions{
		Host:     a.cfg.DB.Host,
		Port:     a.cfg.DB.Port,
		Username: a.cfg.DB.Username,
		Password: a.cfg.DB.Password,
		Database: a.cfg.DB.Database,
	})
	if err != nil {
		return err
	}
	mysql.GormMigrations(db)
	a.db = db
	return nil
}

func NewApp(cfg config.Config) (AppContainer, error) {
	a := &app{
		cfg: cfg,
	}
	if err := a.setDB(); err != nil {
		return nil, err
	}
	a.assetService = asset.NewAssetService(nil, storage.NewOrderRepo(a.db))
	return a, nil
}

func NewMustApp(cfg config.Config) AppContainer {
	a, err := NewApp(cfg)
	if err != nil {
		panic(err)
	}
	return a
}
