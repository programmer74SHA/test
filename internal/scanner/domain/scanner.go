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
	ID          ScannerUUID
	Name        string
	Type        ScannerType
	Description string
	Endpoint    string
	Username    string
	Password    string
	APIKey      string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   time.Time
}

type ScannerFilter struct {
	Name    string
	Type    ScannerType
	Enabled *bool
}

func ScannerUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
