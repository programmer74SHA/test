package storage

import (
	"context"
	"errors"
	"fmt"
	"log"

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

func (r *scannerRepo) Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	s := mapper.ScannerDomain2Storage(scanner)

	log.Printf("Repository: Creating scanner: %+v", s)

	// Create the scanner in the database
	err := r.db.Table("scanners").WithContext(ctx).Create(&s).Error
	if err != nil {
		log.Printf("Repository: Error creating scanner: %v", err)
		return 0, err
	}

	// Return the scanner ID
	return s.ID, nil
}

func (r *scannerRepo) GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Repository: Getting scanner with ID: %d", scannerID)

	var scanner types.Scanner
	err := r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", scannerID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner not found for ID: %d", scannerID)
			return nil, nil
		}
		log.Printf("Repository: Error querying scanner: %v", err)
		return nil, err
	}

	log.Printf("Repository: Successfully retrieved scanner: %+v", scanner)
	domainScanner := mapper.ScannerStorage2Domain(scanner)

	return domainScanner, nil
}

func (r *scannerRepo) Update(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Updating scanner: %+v", scanner)

	s := mapper.ScannerDomain2Storage(scanner)

	// Update the scanner in the database
	result := r.db.Table("scanners").WithContext(ctx).Where("id = ?", scanner.ID).Updates(s)
	if result.Error != nil {
		log.Printf("Repository: Error updating scanner: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when updating scanner with ID: %d", scanner.ID)
		return fmt.Errorf("scanner with ID %d not found", scanner.ID)
	}

	log.Printf("Repository: Successfully updated scanner with ID: %d", scanner.ID)
	return nil
}

func (r *scannerRepo) Delete(ctx context.Context, scannerID int64) error {
	log.Printf("Repository: Deleting scanner with ID: %d", scannerID)

	// Soft delete by updating the deleted_at timestamp
	result := r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", scannerID).
		Update("deleted_at", gorm.Expr("NOW()"))

	if result.Error != nil {
		log.Printf("Repository: Error deleting scanner: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when deleting scanner with ID: %d", scannerID)
		return fmt.Errorf("scanner with ID %d not found", scannerID)
	}

	log.Printf("Repository: Successfully deleted scanner with ID: %d", scannerID)
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
		scanner := mapper.ScannerStorage2Domain(s)
		result = append(result, *scanner)
	}

	return result, nil
}
