package domain

import (
	"time"

	"github.com/google/uuid"
)

type ScannerUUID = uuid.UUID

type ScannerType string

const (
	ScannerTypeNmap    ScannerType = "NMAP"
	ScannerTypeVCenter ScannerType = "VCENTER"
	ScannerTypeDomain  ScannerType = "DOMAIN"
)

type ScannerDomain struct {
	ID          int64 // Changed to int64 to match database
	Name        string
	Type        ScannerType
	Description string
	Endpoint    string
	Username    string
	Password    string
	APIKey      string
	Enabled     bool
	UserID      string // Changed to string to match database
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   time.Time
}

type ScannerFilter struct {
	Name    string
	Type    ScannerType
	Enabled *bool
}

// GetScannerTypeFromInt converts an integer representation to a ScannerType
func GetScannerTypeFromInt(scanType int) ScannerType {
	switch scanType {
	case 1:
		return ScannerTypeNmap
	case 2:
		return ScannerTypeVCenter
	case 3:
		return ScannerTypeDomain
	default:
		return ""
	}
}

// GetIntFromScannerType converts a ScannerType to its integer representation
func GetIntFromScannerType(scanType ScannerType) int {
	switch scanType {
	case ScannerTypeNmap:
		return 1
	case ScannerTypeVCenter:
		return 2
	case ScannerTypeDomain:
		return 3
	default:
		return 0
	}
}
