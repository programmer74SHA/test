package storage

import (
	"context"
	"errors"
	"fmt"

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
	scannerID, err := uuid.Parse(s.ScannerID)
	if err != nil {
		return uuid.Nil, err
	}

	return scannerID, r.db.Table("scanners").WithContext(ctx).Create(&s).Error
}

// If the column name is different in the database schema than what you're using in the code
func (r *scannerRepo) GetByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error) {
	var scanner types.Scanner

	// Try with 'id' instead of 'scanner_id' if that's what's in your database
	err := r.db.Table("scanners").WithContext(ctx).
		Where("scanner_id = ?", scannerUUID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return mapper.ScannerStorage2Domain(scanner)
}

func (r *scannerRepo) Update(ctx context.Context, scanner domain.ScannerDomain) error {
	s := mapper.ScannerDomain2Storage(scanner)
	return r.db.Table("scanners").WithContext(ctx).Where("scanner_id = ?", s.ScannerID).Updates(s).Error
}

func (r *scannerRepo) Delete(ctx context.Context, scannerUUID domain.ScannerUUID) error {
	// Soft delete
	return r.db.Table("scanners").WithContext(ctx).Where("scanner_id = ?", scannerUUID).Update("deleted_at", gorm.Expr("NOW()")).Error
}

func (r *scannerRepo) List(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error) {
	// Change this line to match how your database represents non-deleted records
	query := r.db.Table("scanners").WithContext(ctx).Where("deleted_at = '0000-00-00 00:00:00'")

	// Only apply filters if they are actually provided
	if filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+filter.Name+"%")
	}

	if filter.Type != "" {
		query = query.Where("type = ?", filter.Type)
	}

	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}

	// Add debug to see the actual SQL query
	sqlDb := query.Statement.Dialector.(interface {
		Explain(sql string, vars ...interface{}) string
	})
	fmt.Println("SQL Query:", sqlDb.Explain(query.Statement.SQL.String(), query.Statement.Vars...))

	var scanners []types.Scanner
	err := query.Find(&scanners).Error
	if err != nil {
		return nil, err
	}

	fmt.Printf("DB found %d scanners\n", len(scanners))

	var result []domain.ScannerDomain
	for _, s := range scanners {
		scanner, err := mapper.ScannerStorage2Domain(s)
		if err != nil {
			return nil, err
		}
		result = append(result, *scanner)
	}

	return result, nil
}
