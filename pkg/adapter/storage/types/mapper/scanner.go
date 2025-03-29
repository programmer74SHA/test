package mapper

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// ScannerDomain2Storage converts a domain scanner model to a storage scanner model
func ScannerDomain2Storage(scanner domain.ScannerDomain) *types.Scanner {
	var description *string
	var scanType *int
	var userID *string

	// Convert scanner type to scan_type int
	if scanner.Type != "" {
		typeInt := domain.GetIntFromScannerType(scanner.Type)
		if typeInt > 0 {
			scanType = &typeInt
		}
	}

	if scanner.Description != "" {
		description = &scanner.Description
	}

	if scanner.UserID != uuid.Nil {
		id := scanner.UserID.String()
		userID = &id
	}

	// If there's a stored numeric ID, use it to set the database ID
	var id int64
	if scanner.IDNumeric != "" {
		parsedID, err := strconv.ParseInt(scanner.IDNumeric, 10, 64)
		if err == nil {
			id = parsedID
		}
	}

	return &types.Scanner{
		ID:        id,
		Name:      scanner.Name,
		ScanType:  scanType,
		IsActive:  scanner.Enabled,
		UserID:    userID,
		CreatedAt: scanner.CreatedAt,
		UpdatedAt: &scanner.UpdatedAt,
		DeletedAt: &scanner.DeletedAt,
	}
}

// ScannerStorage2Domain converts a storage scanner model to a domain scanner model
func ScannerStorage2Domain(scanner types.Scanner) (*domain.ScannerDomain, error) {
	// Create a UUID for the domain layer
	scannerUUID := uuid.New()

	// Store the numeric ID in the domain model for future reference
	idNumeric := strconv.FormatInt(scanner.ID, 10)

	var scannerType domain.ScannerType
	if scanner.ScanType != nil {
		scannerType = domain.GetScannerTypeFromInt(*scanner.ScanType)
	}

	var description string

	var userID uuid.UUID
	if scanner.UserID != nil {
		parsedUserID, err := uuid.Parse(*scanner.UserID)
		if err != nil {
			return nil, err
		}
		userID = parsedUserID
	}

	var updatedAt, deletedAt time.Time
	if scanner.UpdatedAt != nil {
		updatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		deletedAt = *scanner.DeletedAt
	}

	return &domain.ScannerDomain{
		ID:          scannerUUID,
		IDNumeric:   idNumeric,
		Name:        scanner.Name,
		Type:        scannerType,
		Description: description,
		Enabled:     scanner.IsActive,
		UserID:      userID,
		CreatedAt:   scanner.CreatedAt,
		UpdatedAt:   updatedAt,
		DeletedAt:   deletedAt,
	}, nil
}

// ScannerFilterDomain2Storage converts a domain scanner filter to a storage scanner filter
func ScannerFilterDomain2Storage(filter domain.ScannerFilter) *types.ScannerFilter {
	return &types.ScannerFilter{
		Name:    filter.Name,
		Type:    string(filter.Type),
		Enabled: filter.Enabled,
	}
}
