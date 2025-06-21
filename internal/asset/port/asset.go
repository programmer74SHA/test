package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

type Repo interface {
	Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error)
	CreateWithScannerType(ctx context.Context, asset domain.AssetDomain, scannerType string) (domain.AssetUUID, error)
	Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error)
	LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error
	StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error
	UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error
	GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error)
	Update(ctx context.Context, asset domain.AssetDomain) error
	DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error)
	GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error)
	GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error)
	ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error)
	GetDistinctOSNames(ctx context.Context) ([]string, error)
}
