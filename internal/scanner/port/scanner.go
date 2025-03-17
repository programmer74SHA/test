package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

type Repo interface {
	Create(ctx context.Context, scanner domain.ScannerDomain) (domain.ScannerUUID, error)
	GetByID(ctx context.Context, UUID domain.ScannerUUID) (*domain.ScannerDomain, error)
	Update(ctx context.Context, scanner domain.ScannerDomain) error
	Delete(ctx context.Context, UUID domain.ScannerUUID) error
	List(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error)
}

type Service interface {
	CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (domain.ScannerUUID, error)
	GetScannerByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error)
	UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error
	DeleteScanner(ctx context.Context, scannerUUID domain.ScannerUUID) error
	ListScanners(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error)
}
