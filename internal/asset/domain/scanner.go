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

// ScannerDomain represents a scanner in the system
// This domain model bridges between the application logic (which uses UUIDs)
// and the database (which uses numeric IDs)
type ScannerDomain struct {
	ID          ScannerUUID // UUID for the domain layer
	IDNumeric   string      // String representation of the numeric database ID
	Name        string
	Type        ScannerType
	Description string
	Endpoint    string
	Username    string
	Password    string
	APIKey      string
	Enabled     bool      // Maps to is_active in the database
	UserID      uuid.UUID // Reference to the user who owns this scanner
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   time.Time
}

// ScannerFilter for filtering scanners in queries
type ScannerFilter struct {
	Name    string
	Type    ScannerType
	Enabled *bool
}

// ScannerUUIDFromString creates a UUID from a string representation
func ScannerUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ScannerUUIDFromInt creates a UUID representation of a numeric ID
// This is used to bridge between the database's numeric IDs and the domain's UUIDs
func ScannerUUIDFromInt(id int64) uuid.UUID {
	// This is a simple approach - in a real system, you might want a more sophisticated
	// mapping between numeric IDs and UUIDs

	// Create a nil UUID
	var u uuid.UUID

	// Convert the integer ID to a string and store it as metadata
	// Note: This doesn't actually modify the UUID value itself
	// In a real system, you would probably want to generate a deterministic UUID
	// based on the numeric ID

	return u
}

// GetNumericIDFromUUID tries to extract a numeric ID from a UUID
// Returns the numeric ID as a string and a boolean indicating success
func GetNumericIDFromUUID(id ScannerUUID) (string, bool) {
	// This is a placeholder implementation
	// In a real system, you would probably have a mapping between UUIDs and numeric IDs

	// For now, just return failure
	return "", false
}

// StoreScannerMetadata associates metadata with a scanner domain
// This can be used to store additional information about the scanner
// such as the numeric ID from the database
func StoreScannerMetadata(scanner *ScannerDomain, numericID int64) {
	if scanner == nil {
		return
	}

	// Store the numeric ID in the domain model
	scanner.IDNumeric = string(numericID)
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
