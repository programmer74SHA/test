package scanner

import (
	"context"
	"errors"
	"log"

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
	log.Printf("Service: Creating scanner: %+v", scanner)

	if scanner.Name == "" || scanner.Type == "" {
		log.Printf("Service: Invalid scanner input - missing name or type")
		return uuid.Nil, ErrInvalidScannerInput
	}

	if scanner.ID == uuid.Nil {
		scanner.ID = uuid.New()
		log.Printf("Service: Assigned new UUID: %s", scanner.ID)
	}

	scannerID, err := s.repo.Create(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error creating scanner: %v", err)
		return uuid.Nil, ErrScannerOnCreate
	}

	log.Printf("Service: Successfully created scanner with ID: %s", scannerID)
	return scannerID, nil
}

func (s *scannerService) GetScannerByID(ctx context.Context, scannerUUID domain.ScannerUUID) (*domain.ScannerDomain, error) {
	log.Printf("Service: Getting scanner with ID: %s", scannerUUID)

	scanner, err := s.repo.GetByID(ctx, scannerUUID)
	if err != nil {
		log.Printf("Service: Error from repository: %v", err)
		return nil, err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %s", scannerUUID)
		return nil, ErrScannerNotFound
	}

	log.Printf("Service: Successfully retrieved scanner: %+v", scanner)
	return scanner, nil
}

func (s *scannerService) UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Service: Updating scanner: %+v", scanner)

	if scanner.ID == uuid.Nil {
		log.Printf("Service: Invalid scanner input - missing ID")
		return ErrInvalidScannerInput
	}

	// Check if scanner exists
	existing, err := s.GetScannerByID(ctx, scanner.ID)
	if err != nil {
		log.Printf("Service: Scanner existence check failed: %v", err)
		return err
	}

	log.Printf("Service: Found existing scanner: %+v", existing)

	err = s.repo.Update(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error updating scanner: %v", err)
		return ErrScannerOnUpdate
	}

	log.Printf("Service: Successfully updated scanner")
	return nil
}

func (s *scannerService) DeleteScanner(ctx context.Context, scannerUUID domain.ScannerUUID) error {
	log.Printf("Service: Deleting scanner with ID: %s", scannerUUID)

	// Check if scanner exists
	_, err := s.GetScannerByID(ctx, scannerUUID)
	if err != nil {
		log.Printf("Service: Scanner existence check failed: %v", err)
		return err
	}

	err = s.repo.Delete(ctx, scannerUUID)
	if err != nil {
		log.Printf("Service: Error deleting scanner: %v", err)
		return ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted scanner")
	return nil
}

func (s *scannerService) ListScanners(ctx context.Context, filter domain.ScannerFilter) ([]domain.ScannerDomain, error) {
	log.Printf("Service: Listing scanners with filter: %+v", filter)

	scanners, err := s.repo.List(ctx, filter)
	if err != nil {
		log.Printf("Service: Error listing scanners: %v", err)
		return nil, err
	}

	log.Printf("Service: Successfully listed %d scanners", len(scanners))
	return scanners, nil
}
