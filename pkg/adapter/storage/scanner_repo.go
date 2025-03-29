package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type scannerRepo struct {
	db *gorm.DB
}

func NewScannerRepo(db *gorm.DB) scannerPort.Repo {
	return &scannerRepo{
		db: db,
	}
}

func (r *scannerRepo) Create(ctx context.Context, scanner domain.ScannerDomain) (domain.ScannerUUID, error) {
	s := mapper.ScannerDomain2Storage(scanner)

	log.Printf("Repository: Creating scanner: %+v", s)

	// Create the scanner in the database
	err := r.db.Table("scanners").WithContext(ctx).Create(&s).Error
	if err != nil {
		log.Printf("Repository: Error creating scanner: %v", err)
		return uuid.Nil, err
	}

	// At this point, the database has assigned an ID to the scanner
	// We need to retrieve the numeric ID and store it in our domain model
	log.Printf("Repository: Scanner created with ID: %d", s.ID)

	// Store the numeric ID in the scanner UUID for reference
	// In a real application, you might want to use a more sophisticated approach
	scanner.IDNumeric = strconv.FormatInt(s.ID, 10)

	// Return the scanner UUID
	return scanner.ID, nil
}

func (r *scannerRepo) GetByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error) {
	log.Printf("Repository: Getting scanner with ID: %s", scannerUUID.String())

	// Try to extract a numeric ID from the scanner domain UUID
	var id int64
	var err error

	// Check if we have a stored numeric ID in the domain model
	if numericID, ok := scanner.GetNumericIDFromUUID(scannerUUID); ok {
		id, err = strconv.ParseInt(numericID, 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing numeric ID: %v", err)
			return nil, err
		}
	} else {
		// If we don't have a stored numeric ID, we need to query by UUID
		// This is a fallback approach and might not work in all cases
		log.Printf("Repository: No numeric ID found, trying to query by UUID: %s", scannerUUID.String())
		id, err = strconv.ParseInt(scannerUUID.String(), 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing UUID as numeric ID: %v", err)
			return nil, err
		}
	}

	var scanner types.Scanner
	err = r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", id).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner not found for ID: %d", id)
			return nil, nil
		}
		log.Printf("Repository: Error querying scanner: %v", err)
		return nil, err
	}

	log.Printf("Repository: Successfully retrieved scanner: %+v", scanner)
	domainScanner, err := mapper.ScannerStorage2Domain(scanner)
	if err != nil {
		log.Printf("Repository: Error mapping scanner: %v", err)
		return nil, err
	}

	return domainScanner, nil
}

func (r *scannerRepo) Update(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Updating scanner: %+v", scanner)

	s := mapper.ScannerDomain2Storage(scanner)

	// Extract the numeric ID from the scanner domain UUID
	var id int64
	var err error

	// Check if we have a stored numeric ID in the domain model
	if scanner.IDNumeric != "" {
		id, err = strconv.ParseInt(scanner.IDNumeric, 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing numeric ID: %v", err)
			return err
		}
	} else {
		// If we don't have a stored numeric ID, we need to query by UUID
		// This is a fallback approach and might not work in all cases
		log.Printf("Repository: No numeric ID found, trying to use UUID: %s", scanner.ID.String())
		id, err = strconv.ParseInt(scanner.ID.String(), 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing UUID as numeric ID: %v", err)
			return err
		}
	}

	// Update the scanner in the database
	result := r.db.Table("scanners").WithContext(ctx).Where("id = ?", id).Updates(s)
	if result.Error != nil {
		log.Printf("Repository: Error updating scanner: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when updating scanner with ID: %d", id)
		return fmt.Errorf("scanner with ID %d not found", id)
	}

	log.Printf("Repository: Successfully updated scanner with ID: %d", id)
	return nil
}

func (r *scannerRepo) Delete(ctx context.Context, scannerUUID domain.ScannerUUID) error {
	log.Printf("Repository: Deleting scanner with UUID: %s", scannerUUID.String())

	// Extract the numeric ID from the scanner domain UUID
	var id int64
	var err error

	// Check if we have a stored numeric ID in the domain model
	if numericID, ok := scanner.GetNumericIDFromUUID(scannerUUID); ok {
		id, err = strconv.ParseInt(numericID, 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing numeric ID: %v", err)
			return err
		}
	} else {
		// If we don't have a stored numeric ID, we need to query by UUID
		// This is a fallback approach and might not work in all cases
		log.Printf("Repository: No numeric ID found, trying to use UUID: %s", scannerUUID.String())
		id, err = strconv.ParseInt(scannerUUID.String(), 10, 64)
		if err != nil {
			log.Printf("Repository: Error parsing UUID as numeric ID: %v", err)
			return err
		}
	}

	// Soft delete by updating the deleted_at timestamp
	result := r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", id).
		Update("deleted_at", gorm.Expr("NOW()"))

	if result.Error != nil {
		log.Printf("Repository: Error deleting scanner: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when deleting scanner with ID: %d", id)
		return fmt.Errorf("scanner with ID %d not found", id)
	}

	log.Printf("Repository: Successfully deleted scanner with ID: %d", id)
	return nil
}

func (r *scannerRepo) List(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error) {
	log.Printf("Repository: Listing scanners with filter: %+v", filter)

	// Start with a basic query for non-deleted records
	query := r.db.Table("scanners").WithContext(ctx).
		Where("deleted_at IS NULL")

	// Apply filters if provided
	if filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+filter.Name+"%")
	}

	if filter.Type != "" {
		var scanType int
		switch filter.Type {
		case domain.ScannerTypeNmap:
			scanType = 1
		case domain.ScannerTypeVCenter:
			scanType = 2
		case domain.ScannerTypeDomain:
			scanType = 3
		default:
			// No filter if type doesn't match
		}

		if scanType > 0 {
			query = query.Where("scan_type = ?", scanType)
		}
	}

	if filter.Enabled != nil {
		query = query.Where("is_active = ?", *filter.Enabled)
	}

	// Debug logging for SQL query
	sqlDb := query.Statement.Dialector.(interface {
		Explain(sql string, vars ...interface{}) string
	})
	fmt.Println("SQL Query:", sqlDb.Explain(query.Statement.SQL.String(), query.Statement.Vars...))

	var scanners []types.Scanner
	err := query.Find(&scanners).Error
	if err != nil {
		log.Printf("Repository: Error listing scanners: %v", err)
		return nil, err
	}

	log.Printf("Repository: Found %d scanners", len(scanners))

	var result []domain.ScannerDomain
	for _, s := range scanners {
		scanner, err := mapper.ScannerStorage2Domain(s)
		if err != nil {
			log.Printf("Repository: Error mapping scanner: %v", err)
			return nil, err
		}
		result = append(result, *scanner)
	}

	return result, nil
}
