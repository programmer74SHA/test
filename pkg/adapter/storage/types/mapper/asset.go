package mapper

import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// AssetDomain2Storage converts a domain asset model to a storage asset model
func AssetDomain2Storage(asset domain.AssetDomain) *types.Asset {
	// Convert UUID to string, then extract a numeric value for the ID
	idStr := asset.ID.String()
	// Extract last 9 characters and convert to int64 (avoiding potential overflow)
	idPart := idStr[len(idStr)-9:]
	id, err := strconv.ParseInt(idPart, 16, 64)
	if err != nil {
		// If conversion fails, use a fallback approach
		id = time.Now().UnixNano() // Use timestamp as fallback ID
	}

	// Handle nullable fields with pointers
	name := &asset.Name
	domainStr := &asset.Domain
	osName := &asset.OSName
	osVersion := &asset.OSVersion
	updatedAt := &asset.UpdatedAt

	return &types.Asset{
		ID:        id,
		Name:      name,
		Domain:    domainStr,
		Hostname:  asset.Hostname,
		IPAddress: asset.IP,
		OSName:    osName,
		OSVersion: osVersion,
		AssetType: asset.Type,
		CreatedAt: asset.CreatedAt,
		UpdatedAt: updatedAt,
	}
}

// AssetStorage2Domain converts a storage asset model to a domain asset model
func AssetStorage2Domain(asset types.Asset) (*domain.AssetDomain, error) {
	// Create a deterministic UUID from int64 ID
	// Format the int64 as a hex string and use it to construct a UUID
	idHex := fmt.Sprintf("%016x", asset.ID)
	uuidStr := fmt.Sprintf("00000000-0000-0000-0000-%s", idHex[:12])

	uid, err := uuid.Parse(uuidStr)
	if err != nil {
		// Fallback to random UUID if parsing fails
		uid, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
	}

	// Handle nullable fields
	name := ""
	if asset.Name != nil {
		name = *asset.Name
	}

	domainStr := ""
	if asset.Domain != nil {
		domainStr = *asset.Domain
	}

	osName := ""
	if asset.OSName != nil {
		osName = *asset.OSName
	}

	osVersion := ""
	if asset.OSVersion != nil {
		osVersion = *asset.OSVersion
	}

	updatedAt := asset.CreatedAt
	if asset.UpdatedAt != nil {
		updatedAt = *asset.UpdatedAt
	}

	return &domain.AssetDomain{
		ID:          uid,
		Name:        name,
		Domain:      domainStr,
		Hostname:    asset.Hostname,
		OSName:      osName,
		OSVersion:   osVersion,
		Type:        asset.AssetType,
		IP:          asset.IPAddress,
		Description: "",
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   updatedAt,
	}, nil
}
