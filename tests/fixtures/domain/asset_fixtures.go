package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// NewTestAssetDomain creates a basic test asset domain with sensible defaults
func NewTestAssetDomain() domain.AssetDomain {
	return domain.AssetDomain{
		ID:               uuid.New(),
		Name:             "Test Asset",
		Domain:           "test.local",
		Hostname:         "test-host",
		OSName:           "Ubuntu",
		OSVersion:        "20.04",
		Type:             "Server",
		Description:      "Test asset for unit tests",
		Risk:             1,
		LoggingCompleted: false,
		AssetValue:       100,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Ports:            []domain.Port{},
		VMwareVMs:        []domain.VMwareVM{},
		AssetIPs:         []domain.AssetIP{},
		Scanner:          nil,
	}
}

// NewTestAssetDomainWithPorts creates a test asset with specified number of ports
func NewTestAssetDomainWithPorts(portCount int) domain.AssetDomain {
	asset := NewTestAssetDomain()
	for i := 0; i < portCount; i++ {
		asset.Ports = append(asset.Ports, NewTestPort(asset.ID.String(), 80+i))
	}
	return asset
}

// NewTestAssetDomainWithIPs creates a test asset with specified IPs
func NewTestAssetDomainWithIPs(ips []string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	for i, ip := range ips {
		asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: NewTestMACAddress(i),
		})
	}
	return asset
}

// NewTestPort creates a test port
func NewTestPort(assetID string, portNumber int) domain.Port {
	return domain.Port{
		ID:             uuid.New().String(),
		AssetID:        assetID,
		PortNumber:     portNumber,
		Protocol:       "tcp",
		State:          "open",
		ServiceName:    "http",
		ServiceVersion: "1.0",
		Description:    "Test port",
		DiscoveredAt:   time.Now(),
	}
}

// NewTestMACAddress generates a test MAC address
func NewTestMACAddress(index int) string {
	return "00:11:22:33:44:" + fmt.Sprintf("%02d", index%100)
}

// NewTestAssetDomainMinimal creates a minimal valid asset for testing
func NewTestAssetDomainMinimal() domain.AssetDomain {
	return domain.AssetDomain{
		ID:        uuid.New(),
		Hostname:  "minimal-host",
		Type:      "Server",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// NewTestAssetDomainWithValidation creates asset for validation testing
func NewTestAssetDomainWithValidation(hostname string, assetType string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.Hostname = hostname
	asset.Type = assetType
	return asset
}

// NewTestAssetDomainWithDuplicateHostname creates asset with hostname for duplicate testing
func NewTestAssetDomainWithDuplicateHostname(hostname string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.Hostname = hostname
	return asset
}

// NewTestAssetDomainWithDuplicateIP creates asset with specific IP for duplicate testing
func NewTestAssetDomainWithDuplicateIP(ip string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.AssetIPs = []domain.AssetIP{
		{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: "00:11:22:33:44:55",
		},
	}
	return asset
}
