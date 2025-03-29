package mapper

import (
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func ScannerDomain2Storage(scanner domain.ScannerDomain) *types.Scanner {
	var description, username, password, apiKey *string

	if scanner.Description != "" {
		description = &scanner.Description
	}

	if scanner.Username != "" {
		username = &scanner.Username
	}

	if scanner.Password != "" {
		password = &scanner.Password
	}

	if scanner.APIKey != "" {
		apiKey = &scanner.APIKey
	}

	return &types.Scanner{
		ScannerID:   scanner.ID.String(),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: description,
		Endpoint:    scanner.Endpoint,
		Username:    username,
		Password:    password,
		APIKey:      apiKey,
		Enabled:     scanner.Enabled,
		CreatedAt:   scanner.CreatedAt,
		UpdatedAt:   &scanner.UpdatedAt,
		DeletedAt:   &scanner.DeletedAt,
	}
}

func ScannerStorage2Domain(scanner types.Scanner) (*domain.ScannerDomain, error) {
	uid, err := domain.ScannerUUIDFromString(scanner.ScannerID)
	if err != nil {
		return nil, err
	}

	var description, username, password, apiKey string

	if scanner.Description != nil {
		description = *scanner.Description
	}

	if scanner.Username != nil {
		username = *scanner.Username
	}

	if scanner.Password != nil {
		password = *scanner.Password
	}

	if scanner.APIKey != nil {
		apiKey = *scanner.APIKey
	}

	var updatedAt, deletedAt time.Time
	if scanner.UpdatedAt != nil {
		updatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		deletedAt = *scanner.DeletedAt
	}

	return &domain.ScannerDomain{
		ID:          uid,
		Name:        scanner.Name,
		Type:        domain.ScannerType(scanner.Type),
		Description: description,
		Endpoint:    scanner.Endpoint,
		Username:    username,
		Password:    password,
		APIKey:      apiKey,
		Enabled:     scanner.Enabled,
		CreatedAt:   scanner.CreatedAt,
		UpdatedAt:   updatedAt,
		DeletedAt:   deletedAt,
	}, nil
}

func ScannerFilterDomain2Storage(filter domain.ScannerFilter) *types.ScannerFilter {
	return &types.ScannerFilter{
		Name:    filter.Name,
		Type:    string(filter.Type),
		Enabled: filter.Enabled,
	}
}
