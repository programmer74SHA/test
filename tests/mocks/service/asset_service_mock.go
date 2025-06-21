package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// MockAssetService is a mock implementation of the assetPort.Service interface
type MockAssetService struct {
	mock.Mock
}

func (m *MockAssetService) CreateAsset(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	args := m.Called(ctx, asset)
	return args.Get(0).(domain.AssetUUID), args.Error(1)
}

func (m *MockAssetService) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUID)
	return args.Get(0).(*domain.AssetDomain), args.Error(1)
}

func (m *MockAssetService) Get(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	args := m.Called(ctx, assetFilter, limit, offset, sortOptions)
	return args.Get(0).([]domain.AssetDomain), args.Get(1).(int), args.Error(2)
}

func (m *MockAssetService) UpdateAsset(ctx context.Context, asset domain.AssetDomain) error {
	args := m.Called(ctx, asset)
	return args.Error(0)
}

func (m *MockAssetService) DeleteAssets(ctx context.Context, ids []string, filter *domain.AssetFilters, exclude bool) error {
	args := m.Called(ctx, ids, filter, exclude)
	return args.Error(0)
}

func (m *MockAssetService) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs)
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetService) GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs, sortOptions)
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetService) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	args := m.Called(ctx, assetIDs, exportType, selectedColumns)
	return args.Get(0).(*domain.ExportData), args.Error(1)
}

func (m *MockAssetService) GenerateCSV(ctx context.Context, exportData *domain.ExportData) ([]byte, error) {
	args := m.Called(ctx, exportData)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAssetService) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}
