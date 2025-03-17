package storage

import (
	"context"
	"errors"

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

func (r *scannerRepo) GetByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error) {
	var scanner types.Scanner
	err := r.db.Table("scanners").WithContext(ctx).Where("scanner_id = ? AND deleted_at IS NULL", scannerUUID).First(&scanner).Error
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
	f := mapper.ScannerFilterDomain2Storage(filter)
	var scanners []types.Scanner

	query := r.db.Table("scanners").WithContext(ctx).Where("deleted_at IS NULL")

	if f.Name != "" {
		query = query.Where("name LIKE ?", "%"+f.Name+"%")
	}

	if f.Type != "" {
		query = query.Where("type = ?", f.Type)
	}

	if f.Enabled != nil {
		query = query.Where("enabled = ?", *f.Enabled)
	}

	err := query.Find(&scanners).Error
	if err != nil {
		return nil, err
	}

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
