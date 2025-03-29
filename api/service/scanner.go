package service

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
)

var (
	ErrScannerOnCreate     = scanner.ErrScannerOnCreate
	ErrScannerOnUpdate     = scanner.ErrScannerOnUpdate
	ErrScannerOnDelete     = scanner.ErrScannerOnDelete
	ErrScannerNotFound     = scanner.ErrScannerNotFound
	ErrInvalidScannerInput = scanner.ErrInvalidScannerInput
)

type ScannerService struct {
	service scannerPort.Service
}

func NewScannerService(srv scannerPort.Service) *ScannerService {
	return &ScannerService{
		service: srv,
	}
}

func (s *ScannerService) CreateScanner(ctx context.Context, req *pb.CreateScannerRequest) (*pb.Scanner, error) {
	// Validate required fields
	if req.GetName() == "" || req.GetType() == "" || req.GetEndpoint() == "" {
		return nil, ErrInvalidScannerInput
	}

	scanner := domain.ScannerDomain{
		Name:        req.GetName(),
		Type:        domain.ScannerType(req.GetType()),
		Description: req.GetDescription(),
		Endpoint:    req.GetEndpoint(),
		APIKey:      req.GetApiKey(),
		Enabled:     req.GetEnabled(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	id, err := s.service.CreateScanner(ctx, scanner)
	if err != nil {
		return nil, err
	}

	return &pb.Scanner{
		Id:          strconv.FormatInt(id, 10),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) GetScanner(ctx context.Context, req *pb.GetScannerRequest) (*pb.Scanner, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return nil, ErrInvalidScannerInput
	}

	scanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &pb.Scanner{
		Id:          strconv.FormatInt(scanner.ID, 10),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) UpdateScanner(ctx context.Context, req *pb.UpdateScannerRequest) (*pb.Scanner, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return nil, ErrInvalidScannerInput
	}

	// Get existing scanner
	existingScanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return nil, err
	}

	scanner := *existingScanner
	scanner.Name = req.GetName()
	scanner.Type = domain.ScannerType(req.GetType())
	scanner.Description = req.GetDescription()
	scanner.Endpoint = req.GetEndpoint()
	scanner.APIKey = req.GetApiKey()
	scanner.Enabled = req.GetEnabled()
	scanner.UpdatedAt = time.Now()

	err = s.service.UpdateScanner(ctx, scanner)
	if err != nil {
		return nil, err
	}

	return &pb.Scanner{
		Id:          strconv.FormatInt(scanner.ID, 10),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) DeleteScanner(ctx context.Context, req *pb.DeleteScannerRequest) error {
	log.Printf("API Service: Deleting scanner with ID: %s", req.GetId())

	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		log.Printf("API Service: Invalid scanner ID format: %v", err)
		return ErrInvalidScannerInput
	}

	err = s.service.DeleteScanner(ctx, id)
	if err != nil {
		log.Printf("API Service: Error from service layer: %v", err)
		return err
	}

	log.Printf("API Service: Successfully deleted scanner")
	return nil
}

func (s *ScannerService) DeleteScanners(ctx context.Context, req *pb.DeleteScannersRequest) error {
	for _, idStr := range req.GetIds() {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			// Continue with other IDs even if one is invalid
			continue
		}

		err = s.service.DeleteScanner(ctx, id)
		if err != nil && !errors.Is(err, ErrScannerNotFound) {
			return err
		}
	}

	return nil
}

func (s *ScannerService) ListScanners(ctx context.Context, req *pb.ListScannersRequest) (*pb.ListScannersResponse, error) {
	var enabledFilter *bool
	if req.EnabledFilter {
		enabledFilter = &req.EnabledFilter
	}

	filter := domain.ScannerFilter{
		Name:    req.GetNameFilter(),
		Type:    domain.ScannerType(req.GetTypeFilter()),
		Enabled: enabledFilter,
	}

	scanners, err := s.service.ListScanners(ctx, filter)
	if err != nil {
		return nil, err
	}

	var pbScanners []*pb.Scanner
	for _, scanner := range scanners {
		pbScanners = append(pbScanners, &pb.Scanner{
			Id:          strconv.FormatInt(scanner.ID, 10),
			Name:        scanner.Name,
			Type:        string(scanner.Type),
			Description: scanner.Description,
			Endpoint:    scanner.Endpoint,
			ApiKey:      scanner.APIKey,
			Enabled:     scanner.Enabled,
		})
	}

	return &pb.ListScannersResponse{
		Scanners: pbScanners,
	}, nil
}

func (s *ScannerService) BatchUpdateScannersEnabled(ctx context.Context, req *pb.BatchUpdateScannersEnabledRequest) error {
	log.Printf("API Service: Batch updating scanners, enabled=%v, IDs count: %d", req.GetEnabled(), len(req.GetIds()))

	if len(req.GetIds()) == 0 {
		log.Printf("API Service: Empty scanner ID list provided")
		return nil // Nothing to update
	}

	var ids []int64
	for _, idStr := range req.GetIds() {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			log.Printf("API Service: Invalid scanner ID format: %s, error: %v", idStr, err)
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		log.Printf("API Service: No valid scanner IDs to process")
		return nil
	}

	// Call the service method with the parsed IDs and enabled status
	err := s.service.BatchUpdateScannersEnabled(ctx, ids, req.GetEnabled())
	if err != nil {
		log.Printf("API Service: Error from service layer: %v", err)
		return err
	}

	log.Printf("API Service: Successfully batch updated scanners")
	return nil
}
