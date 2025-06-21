package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	httpHandlers "gitlab.apk-group.net/siem/backend/asset-discovery/api/handlers/http"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	apiFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/api"
	internalMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/service"
)

// TestCreateAsset_Handler tests the HTTP handler layer integration
// This test focuses on HTTP request/response handling and uses the actual API service layer
func TestCreateAsset_Handler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:        "successful asset creation",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(testUUID, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "id")
			},
		},
		{
			name:        "IP already exists error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.UUID{}, service.ErrIPAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "IP address already exists")
			},
		},
		{
			name:        "hostname already exists error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.UUID{}, service.ErrHostnameAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Hostname already exists")
			},
		},
		{
			name:        "invalid JSON request body",
			requestBody: "invalid json",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:        "internal server error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(uuid.UUID{}, errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

			// Create request body
			var bodyBytes []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			// Make request
			req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// Additional simplified tests for basic HTTP functionality
func TestCreateAsset_Handler_HTTPBasics(t *testing.T) {
	// This test verifies basic HTTP functionality without complex mocking
	app := fiber.New()

	// Use a minimal service getter for basic testing
	serviceGetter := func(ctx context.Context) *service.AssetService {
		mockService := new(internalMocks.MockAssetService)
		return service.NewAssetService(mockService)
	}

	app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

	t.Run("invalid_content_type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString("test"))
		// Don't set Content-Type header

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("empty_body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer([]byte{}))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		// This might return 400 (bad request) due to empty JSON
		assert.True(t, resp.StatusCode >= 400)
	})
}

// TestCreateAsset_Handler_EdgeCases tests various edge cases and HTTP-specific scenarios
func TestCreateAsset_Handler_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func() (*http.Request, error)
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name: "large JSON payload",
			setupRequest: func() (*http.Request, error) {
				largeRequest := apiFixtures.NewTestCreateAssetRequestWithPorts(100) // Large number of ports
				bodyBytes, err := json.Marshal(largeRequest)
				if err != nil {
					return nil, err
				}
				req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return len(asset.Ports) == 100
				})).Return(testUUID, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "id")
			},
		},
		{
			name: "malformed JSON",
			setupRequest: func() (*http.Request, error) {
				req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString(`{"name": "test", "unclosed": `))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as JSON parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name: "empty request body",
			setupRequest: func() (*http.Request, error) {
				req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer([]byte{}))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as empty body should fail validation
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

			// Setup request
			req, err := tt.setupRequest()
			assert.NoError(t, err)

			// Make request
			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}
