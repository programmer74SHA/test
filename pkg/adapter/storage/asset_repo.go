package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type assetRepo struct {
	db *gorm.DB
}

func NewOrderRepo(db *gorm.DB) assetPort.Repo {
	return &assetRepo{
		db: db,
	}
}

func (r *assetRepo) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	a := mapper.AssetDomain2Storage(asset)
	assetID, err := uuid.Parse(a.ID)
	if err != nil {
		// TODO error handling
		panic("cannot pars uuid")
	}

	return assetID, r.db.Table("assets").WithContext(ctx).Create(&a).Error
}

func (r *assetRepo) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	var asset types.Asset
	err := r.db.Table("assets").WithContext(ctx).Where("id = ?", assetUUID).First(&asset).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if asset.ID == "" {
		return nil, nil
	}
	return mapper.AssetStorage2Domain(asset)
}

func (r *assetRepo) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	panic("not implemented")
}
