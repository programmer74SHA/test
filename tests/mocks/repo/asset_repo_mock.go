package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// MockAssetRepo is a mock implementation of the assetPort.Repo interface
type MockAssetRepo struct {
	mock.Mock
}

func (m *MockAssetRepo) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	args := m.Called(ctx, asset)
	return args.Get(0).(domain.AssetUUID), args.Error(1)
}

func (m *MockAssetRepo) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetFilter)
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs)
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs, sortOptions)
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	args := m.Called(ctx, assetFilter, limit, offset, sortOptions)
	return args.Get(0).([]domain.AssetDomain), args.Get(1).(int), args.Error(2)
}

func (m *MockAssetRepo) Update(ctx context.Context, asset domain.AssetDomain) error {
	args := m.Called(ctx, asset)
	return args.Error(0)
}

func (m *MockAssetRepo) DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockAssetRepo) LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error {
	args := m.Called(ctx, assetID, scanJobID)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error {
	args := m.Called(ctx, vmData)
	return args.Error(0)
}

func (m *MockAssetRepo) UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error {
	args := m.Called(ctx, assetID, ports)
	return args.Error(0)
}

func (m *MockAssetRepo) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	args := m.Called(ctx, assetIDs, exportType, selectedColumns)
	return args.Get(0).(*domain.ExportData), args.Error(1)
}

func (m *MockAssetRepo) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}
