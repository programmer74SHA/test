package mapper

import (
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// ScannerDomain2Storage converts a domain scanner model to a storage scanner model
func ScannerDomain2Storage(scanner domain.ScannerDomain) *types.ScannerModel {
	var scanType *int
	var userID *string

	// Convert scanner type to scan_type int
	if scanner.Type != "" {
		typeInt := domain.GetIntFromScannerType(scanner.Type)
		if typeInt > 0 {
			scanType = &typeInt
		}
	}

	if scanner.UserID != "" {
		userID = &scanner.UserID
	}

	return &types.ScannerModel{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanType,
		IsActive:  scanner.Enabled,
		Endpoint:  scanner.Endpoint,
		Username:  scanner.Username,
		Password:  scanner.Password,
		ApiKey:    scanner.APIKey,
		UserID:    userID,
		CreatedAt: scanner.CreatedAt,
		UpdatedAt: &scanner.UpdatedAt,
		DeletedAt: &scanner.DeletedAt,
	}
}

// ScannerStorage2Domain converts a storage scanner model to a domain scanner model
func ScannerStorage2Domain(scanner types.ScannerModel) *domain.ScannerDomain {
	var scannerType domain.ScannerType
	if scanner.ScanType != nil {
		scannerType = domain.GetScannerTypeFromInt(*scanner.ScanType)
	}

	var userID string
	if scanner.UserID != nil {
		userID = *scanner.UserID
	}

	var updatedAt, deletedAt time.Time
	if scanner.UpdatedAt != nil {
		updatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		deletedAt = *scanner.DeletedAt
	}

	return &domain.ScannerDomain{
		ID:          scanner.ID,
		Name:        scanner.Name,
		Type:        scannerType,
		Description: "",
		Endpoint:    scanner.Endpoint,
		Username:    scanner.Username,
		Password:    scanner.Password,
		APIKey:      scanner.ApiKey,
		Enabled:     scanner.IsActive,
		UserID:      userID,
		CreatedAt:   scanner.CreatedAt,
		UpdatedAt:   updatedAt,
		DeletedAt:   deletedAt,
	}
}

// ScannerFilterDomain2Storage converts a domain scanner filter to a storage scanner filter
func ScannerFilterDomain2Storage(filter domain.ScannerFilter) *types.ScannerModelFilter {
	return &types.ScannerModelFilter{
		Name:    filter.Name,
		Type:    string(filter.Type),
		Enabled: filter.Enabled,
	}
}
