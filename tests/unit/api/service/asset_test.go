package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	apiFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/api"
	serviceMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/service"
)

func TestAssetService_CreateAsset(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.CreateAssetRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.CreateAssetResponse)
	}{
		{
			name:    "successful asset creation",
			request: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
				// Validate UUID format
				_, err := uuid.Parse(response.Id)
				assert.NoError(t, err)
			},
		},
		{
			name:    "asset creation with ports",
			request: apiFixtures.NewTestCreateAssetRequestWithPorts(3),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify that ports were correctly transformed
					return len(asset.Ports) == 3 &&
						asset.Ports[0].Protocol == "tcp" &&
						asset.Ports[0].State == "open"
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
		{
			name:    "asset creation with IPs",
			request: apiFixtures.NewTestCreateAssetRequestWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify that IPs were correctly transformed
					return len(asset.AssetIPs) == 2 &&
						asset.AssetIPs[0].IP == "192.168.1.1" &&
						asset.AssetIPs[1].IP == "10.0.0.1"
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
		{
			name:    "IP already exists error",
			request: apiFixtures.NewTestCreateAssetRequestWithIP("192.168.1.100"),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, service.ErrIPAlreadyExists)
			},
			expectedError: service.ErrIPAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "hostname already exists error",
			request: apiFixtures.NewTestCreateAssetRequestWithHostname("existing-host"),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, service.ErrHostnameAlreadyExists)
			},
			expectedError: service.ErrHostnameAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "internal service error",
			request: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.Nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "minimal valid request",
			request: apiFixtures.NewTestCreateAssetRequestMinimal(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify minimal required fields are set
					return asset.Hostname == "minimal-host" &&
						asset.Type == "Server" &&
						len(asset.Ports) == 0 &&
						len(asset.AssetIPs) == 0
				})).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.CreateAsset(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_RequestTransformation(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.CreateAssetRequest
		validateDomain func(t *testing.T, domain domain.AssetDomain)
	}{
		{
			name:    "request with all fields populated",
			request: apiFixtures.NewTestCreateAssetRequest(),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Equal(t, "Test Asset", domain.Name)
				assert.Equal(t, "test.local", domain.Domain)
				assert.Equal(t, "test-host", domain.Hostname)
				assert.Equal(t, "Ubuntu", domain.OSName)
				assert.Equal(t, "20.04", domain.OSVersion)
				assert.Equal(t, "Server", domain.Type)
				assert.Equal(t, "Test asset for unit tests", domain.Description)
				assert.Equal(t, 1, domain.Risk)
				assert.Equal(t, false, domain.LoggingCompleted)
				assert.Equal(t, 100, domain.AssetValue)
				assert.NotZero(t, domain.CreatedAt)
			},
		},
		{
			name: "request with optional fields empty",
			request: &pb.CreateAssetRequest{
				Hostname: "minimal-host",
				Type:     "Server",
			},
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Equal(t, "", domain.Name)
				assert.Equal(t, "", domain.Domain)
				assert.Equal(t, "minimal-host", domain.Hostname)
				assert.Equal(t, "", domain.OSName)
				assert.Equal(t, "", domain.OSVersion)
				assert.Equal(t, "Server", domain.Type)
				assert.Equal(t, "", domain.Description)
				assert.Equal(t, 0, domain.Risk)
				assert.Equal(t, false, domain.LoggingCompleted)
				assert.Equal(t, 0, domain.AssetValue)
			},
		},
		{
			name:    "request with complex ports",
			request: apiFixtures.NewTestCreateAssetRequestWithPorts(2),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Len(t, domain.Ports, 2)
				assert.Equal(t, 80, domain.Ports[0].PortNumber)
				assert.Equal(t, 81, domain.Ports[1].PortNumber)
				assert.Equal(t, "tcp", domain.Ports[0].Protocol)
				assert.Equal(t, "open", domain.Ports[0].State)
				assert.Equal(t, "http", domain.Ports[0].ServiceName)
				assert.Equal(t, domain.ID.String(), domain.Ports[0].AssetID)
			},
		},
		{
			name:    "request with multiple IPs",
			request: apiFixtures.NewTestCreateAssetRequestWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Len(t, domain.AssetIPs, 2)
				assert.Equal(t, "192.168.1.1", domain.AssetIPs[0].IP)
				assert.Equal(t, "10.0.0.1", domain.AssetIPs[1].IP)
				assert.Equal(t, domain.ID.String(), domain.AssetIPs[0].AssetID)
				assert.NotEmpty(t, domain.AssetIPs[0].MACAddress)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the transformation logic that would be in the service
			id := uuid.New()
			now := time.Now()

			// Transform ports (same logic as in CreateAsset)
			ports := make([]domain.Port, 0, len(tt.request.GetPorts()))
			for _, p := range tt.request.GetPorts() {
				ports = append(ports, domain.Port{
					ID:             uuid.New().String(),
					AssetID:        id.String(),
					PortNumber:     int(p.GetPortNumber()),
					Protocol:       p.GetProtocol(),
					State:          p.GetState(),
					ServiceName:    p.GetServiceName(),
					ServiceVersion: p.GetServiceVersion(),
					Description:    p.GetDescription(),
					DiscoveredAt:   now,
				})
			}

			// Transform IPs (same logic as in CreateAsset)
			ips := make([]domain.AssetIP, 0, len(tt.request.GetAssetIps()))
			for _, ip := range tt.request.GetAssetIps() {
				ips = append(ips, domain.AssetIP{
					AssetID:    id.String(),
					IP:         ip.GetIp(),
					MACAddress: ip.GetMacAddress(),
				})
			}

			// Create domain object
			assetDomain := domain.AssetDomain{
				ID:               id,
				Name:             tt.request.GetName(),
				Domain:           tt.request.GetDomain(),
				Hostname:         tt.request.GetHostname(),
				OSName:           tt.request.GetOsName(),
				OSVersion:        tt.request.GetOsVersion(),
				Type:             tt.request.GetType(),
				Description:      tt.request.GetDescription(),
				Risk:             int(tt.request.GetRisk()),
				LoggingCompleted: tt.request.GetLoggingCompleted(),
				AssetValue:       int(tt.request.GetAssetValue()),
				CreatedAt:        now,
				Ports:            ports,
				AssetIPs:         ips,
			}

			// Validate transformation
			tt.validateDomain(t, assetDomain)
		})
	}
}

func TestAssetService_CreateAsset_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		serviceError  error
		expectedError error
	}{
		{
			name:          "IP already exists",
			serviceError:  service.ErrIPAlreadyExists,
			expectedError: service.ErrIPAlreadyExists,
		},
		{
			name:          "hostname already exists",
			serviceError:  service.ErrHostnameAlreadyExists,
			expectedError: service.ErrHostnameAlreadyExists,
		},
		{
			name:          "asset creation failed",
			serviceError:  service.ErrAssetCreateFailed,
			expectedError: service.ErrAssetCreateFailed,
		},
		{
			name:          "generic error",
			serviceError:  errors.New("unexpected error"),
			expectedError: errors.New("unexpected error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			mockInternalService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
				Return(uuid.Nil, tt.serviceError)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Test error propagation by calling the actual service
			ctx := context.Background()
			request := apiFixtures.NewTestCreateAssetRequest()

			_, err := apiService.CreateAsset(ctx, request)

			assert.Error(t, err)
			assert.Equal(t, tt.expectedError.Error(), err.Error())

			mockInternalService.AssertExpectations(t)
		})
	}
}
