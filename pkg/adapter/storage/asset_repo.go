package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"

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

	// No need to parse the ID as a UUID since it's now an int64
	// Instead, we'll store the asset and return the original UUID

	err := r.db.Table("assets").WithContext(ctx).Create(&a).Error
	if err != nil {
		return uuid.Nil, err
	}

	return asset.ID, nil
}

func (r *assetRepo) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	var asset types.Asset

	// Convert the UUID to int64 for database lookup
	idStr := assetUUID.String()
	idPart := idStr[len(idStr)-9:]
	id, err := strconv.ParseInt(idPart, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ID format: %v", err)
	}

	err = r.db.Table("assets").WithContext(ctx).Where("id = ?", id).First(&asset).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	// Check if we got a valid record
	if asset.ID == 0 {
		return nil, nil
	}

	return mapper.AssetStorage2Domain(asset)
}

func (r *assetRepo) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	// Start with a base query
	query := r.db.Table("assets").WithContext(ctx)

	// Apply filters
	if assetFilter.Name != "" {
		query = query.Where("name = ?", assetFilter.Name)
	}
	if assetFilter.Domain != "" {
		query = query.Where("domain = ?", assetFilter.Domain)
	}
	if assetFilter.Hostname != "" {
		query = query.Where("hostname = ?", assetFilter.Hostname)
	}
	if assetFilter.OSName != "" {
		query = query.Where("os_name = ?", assetFilter.OSName)
	}
	if assetFilter.OSVersion != "" {
		query = query.Where("os_version = ?", assetFilter.OSVersion)
	}
	if assetFilter.Type != "" {
		query = query.Where("asset_type = ?", assetFilter.Type)
	}
	if assetFilter.IP != "" {
		query = query.Where("ip_address = ?", assetFilter.IP)
	}

	// Execute the query
	var assets []types.Asset
	err := query.Find(&assets).Error
	if err != nil {
		return nil, err
	}

	// Convert storage models to domain models
	result := make([]domain.AssetDomain, 0, len(assets))
	for _, a := range assets {
		domainAsset, err := mapper.AssetStorage2Domain(a)
		if err != nil {
			// Log the error but continue processing other assets
			continue
		}
		result = append(result, *domainAsset)
	}

	return result, nil
}
