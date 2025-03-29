package mapper

import (
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func AssetDomain2Storage(asset domain.AssetDomain) *types.Asset {
	return &types.Asset{
		ID:        asset.ID.String(),
		Name:      &asset.Name,
		Domain:    &asset.Domain,
		Hostname:  asset.Hostname,
		IPAddress: asset.IP,
		OSName:    &asset.OSName,
		OSVersion: &asset.OSVersion,
		AssetType: asset.Type,
		CreatedAt: asset.CreatedAt,
		UpdatedAt: &asset.UpdatedAt,
	}
}

func AssetStorage2Domain(asset types.Asset) (*domain.AssetDomain, error) {
	uid, err := domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	name := ""
	if asset.Name != nil {
		name = *asset.Name
	}

	domain := ""
	if asset.Domain != nil {
		domain = *asset.Domain
	}

	osName := ""
	if asset.OSName != nil {
		osName = *asset.OSName
	}

	osVersion := ""
	if asset.OSVersion != nil {
		osVersion = *asset.OSVersion
	}

	updateAt := asset.CreatedAt
	if asset.UpdatedAt != nil {
		updateAt = *asset.UpdatedAt
	}

	return &domain.AssetDomain{
		ID:          uid,
		Name:        name,
		Domain:      domain,
		Hostname:    asset.Hostname,
		OSName:      osName,
		OSVersion:   osVersion,
		Type:        asset.AssetType,
		IP:          asset.IPAddress,
		Description: "",
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   updateAt,
	}, nil
}
