package asset_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
	repoMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/repo"
)

func TestAssetService_CreateAsset(t *testing.T) {
	tests := []struct {
		name           string
		inputAsset     domain.AssetDomain
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, assetID domain.AssetUUID, err error)
	}{
		{
			name:       "successful asset creation",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with ports",
			inputAsset: domainFixtures.NewTestAssetDomainWithPorts(3),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: ports should be associated with asset
					return len(asset.Ports) == 3 &&
						asset.Ports[0].AssetID == asset.ID.String()
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with IPs",
			inputAsset: domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: IPs should be associated with asset
					return len(asset.AssetIPs) == 2 &&
						asset.AssetIPs[0].AssetID == asset.ID.String() &&
						asset.AssetIPs[1].AssetID == asset.ID.String()
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "IP already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateIP("192.168.1.100"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, domain.ErrIPAlreadyExists)
			},
			expectedError: domain.ErrIPAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrIPAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "hostname already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateHostname("existing-host"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, domain.ErrHostnameAlreadyExists)
			},
			expectedError: domain.ErrHostnameAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "repository error mapped to service error",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetCreateFailed,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetCreateFailed, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "minimal asset creation",
			inputAsset: domainFixtures.NewTestAssetDomainMinimal(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify minimal requirements are met
					return asset.Hostname == "minimal-host" &&
						asset.Type == "Server" &&
						len(asset.Ports) == 0 &&
						len(asset.AssetIPs) == 0
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service with mock repository
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			assetID, err := service.CreateAsset(ctx, tt.inputAsset)

			// Assert
			tt.validateResult(t, assetID, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_BusinessLogic(t *testing.T) {
	tests := []struct {
		name          string
		setupAsset    func() domain.AssetDomain
		validateLogic func(t *testing.T, asset domain.AssetDomain)
	}{
		{
			name: "asset ID consistency across ports and IPs",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				asset.Ports = []domain.Port{
					domainFixtures.NewTestPort(asset.ID.String(), 80),
					domainFixtures.NewTestPort(asset.ID.String(), 443),
				}
				asset.AssetIPs = []domain.AssetIP{
					{AssetID: asset.ID.String(), IP: "192.168.1.1", MACAddress: "00:11:22:33:44:55"},
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// All ports should have the same asset ID
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				// All IPs should have the same asset ID
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
		{
			name: "timestamp validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomain()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.False(t, asset.CreatedAt.IsZero())
				assert.False(t, asset.UpdatedAt.IsZero())
				// CreatedAt should be before or equal to UpdatedAt
				assert.True(t, asset.CreatedAt.Before(asset.UpdatedAt) || asset.CreatedAt.Equal(asset.UpdatedAt))
			},
		},
		{
			name: "default values validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomainMinimal()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// Required fields should be set
				assert.NotEmpty(t, asset.Hostname)
				assert.NotEmpty(t, asset.Type)
				assert.NotEqual(t, uuid.Nil, asset.ID)

				// Optional fields can be empty/zero values
				assert.Equal(t, "", asset.Name)
				assert.Equal(t, "", asset.Domain)
				assert.Equal(t, 0, asset.Risk)
				assert.Equal(t, false, asset.LoggingCompleted)
			},
		},
		{
			name: "asset with maximum complexity",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				// Add multiple ports
				for i := 0; i < 10; i++ {
					asset.Ports = append(asset.Ports, domainFixtures.NewTestPort(asset.ID.String(), 80+i))
				}
				// Add multiple IPs
				for i := 0; i < 5; i++ {
					asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
						AssetID:    asset.ID.String(),
						IP:         fmt.Sprintf("192.168.1.%d", i+1),
						MACAddress: domainFixtures.NewTestMACAddress(i),
					})
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.Equal(t, 10, len(asset.Ports))
				assert.Equal(t, 5, len(asset.AssetIPs))

				// Verify all relationships are correct
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			assetDomain := tt.setupAsset()

			// Validate business logic
			tt.validateLogic(t, assetDomain)

			// Setup mock repo for service test
			mockRepo := new(repoMocks.MockAssetRepo)
			expectedID := uuid.New()
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
				Return(expectedID, nil)

			// Create service and test
			service := asset.NewAssetService(mockRepo)
			ctx := context.Background()

			resultID, err := service.CreateAsset(ctx, assetDomain)

			assert.NoError(t, err)
			assert.Equal(t, expectedID, resultID)
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name            string
		repositoryError error
		expectedError   error
		errorMessage    string
	}{
		{
			name:            "IP already exists should pass through",
			repositoryError: domain.ErrIPAlreadyExists,
			expectedError:   domain.ErrIPAlreadyExists,
			errorMessage:    "IP address already exists",
		},
		{
			name:            "hostname already exists should pass through",
			repositoryError: domain.ErrHostnameAlreadyExists,
			expectedError:   domain.ErrHostnameAlreadyExists,
			errorMessage:    "Hostname already exists",
		},
		{
			name:            "database connection error should map to create failed",
			repositoryError: errors.New("database connection failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "transaction rollback error should map to create failed",
			repositoryError: errors.New("transaction rollback failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "constraint violation should map to create failed",
			repositoryError: errors.New("constraint violation"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
				Return(uuid.Nil, tt.repositoryError)

			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			testAsset := domainFixtures.NewTestAssetDomain()

			assetID, err := service.CreateAsset(ctx, testAsset)

			// Assert
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, uuid.Nil, assetID)

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ConcurrentAccess(t *testing.T) {
	// This test validates that the service handles concurrent asset creation attempts
	t.Run("concurrent creation with same hostname should fail for second attempt", func(t *testing.T) {
		mockRepo := new(repoMocks.MockAssetRepo)

		// First call succeeds
		firstID := uuid.New()
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		})).Return(firstID, nil).Once()

		// Second call fails with hostname already exists
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		})).Return(uuid.Nil, domain.ErrHostnameAlreadyExists).Once()

		service := asset.NewAssetService(mockRepo)
		ctx := context.Background()

		// First asset creation
		asset1 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID1, err1 := service.CreateAsset(ctx, asset1)

		assert.NoError(t, err1)
		assert.Equal(t, firstID, resultID1)

		// Second asset creation with same hostname
		asset2 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID2, err2 := service.CreateAsset(ctx, asset2)

		assert.Error(t, err2)
		assert.Equal(t, domain.ErrHostnameAlreadyExists, err2)
		assert.Equal(t, uuid.Nil, resultID2)

		mockRepo.AssertExpectations(t)
	})
}
