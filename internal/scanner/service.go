package scanner

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
)

var (
	ErrScannerOnCreate     = errors.New("error on creating new scanner")
	ErrScannerOnUpdate     = errors.New("error on updating scanner")
	ErrScannerOnDelete     = errors.New("error on deleting scanner")
	ErrScannerNotFound     = errors.New("scanner not found")
	ErrInvalidScannerInput = errors.New("invalid scanner input")
)

type scannerService struct {
	repo scannerPort.Repo
}

func NewScannerService(repo scannerPort.Repo) scannerPort.Service {
	return &scannerService{
		repo: repo,
	}
}

func (s *scannerService) CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (domain.ScannerUUID, error) {
	if scanner.Name == "" || scanner.Type == "" {
		return uuid.Nil, ErrInvalidScannerInput
	}

	if scanner.ID == uuid.Nil {
		scanner.ID = uuid.New()
	}

	scannerID, err := s.repo.Create(ctx, scanner)
	if err != nil {
		return uuid.Nil, ErrScannerOnCreate
	}

	return scannerID, nil
}

func (s *scannerService) GetScannerByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error) {
	scanner, err := s.repo.GetByID(ctx, scannerUUID)
	if err != nil {
		return nil, err
	}

	if scanner == nil {
		return nil, ErrScannerNotFound
	}

	return scanner, nil
}

func (s *scannerService) UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error {
	if scanner.ID == uuid.Nil {
		return ErrInvalidScannerInput
	}

	// Check if scanner exists
	_, err := s.GetScannerByID(ctx, scanner.ID)
	if err != nil {
		return err
	}

	err = s.repo.Update(ctx, scanner)
	if err != nil {
		return ErrScannerOnUpdate
	}

	return nil
}

func (s *scannerService) DeleteScanner(ctx context.Context, scannerUUID domain.ScannerUUID) error {
	// Check if scanner exists
	_, err := s.GetScannerByID(ctx, scannerUUID)
	if err != nil {
		return err
	}

	err = s.repo.Delete(ctx, scannerUUID)
	if err != nil {
		return ErrScannerOnDelete
	}

	return nil
}

func (s *scannerService) ListScanners(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error) {
	return s.repo.List(ctx, filter)
}
