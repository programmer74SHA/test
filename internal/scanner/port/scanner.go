package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

type Repo interface {
	Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error)
	GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error)
	Update(ctx context.Context, scanner domain.ScannerDomain) error
	Delete(ctx context.Context, scannerID int64) error
	List(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error)
	// Added method for batch operations
	BatchUpdateEnabled(ctx context.Context, scannerIDs []int64, enabled bool) error
}

type Service interface {
	CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (int64, error)
	GetScannerByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error)
	UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error
	DeleteScanner(ctx context.Context, scannerID int64) error
	ListScanners(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error)
	// Added method for batch operations
	BatchUpdateScannersEnabled(ctx context.Context, scannerIDs []int64, enabled bool) error
}
