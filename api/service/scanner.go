package service

import (
	"context"
	"time"

	"github.com/google/uuid"
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
	scanner := domain.ScannerDomain{
		ID:          uuid.New(),
		Name:        req.GetName(),
		Type:        domain.ScannerType(req.GetType()),
		Description: req.GetDescription(),
		Endpoint:    req.GetEndpoint(),
		Username:    req.GetUsername(),
		Password:    req.GetPassword(),
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
		Id:          id.String(),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		Username:    scanner.Username,
		Password:    scanner.Password,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) GetScanner(ctx context.Context, req *pb.GetScannerRequest) (*pb.Scanner, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, ErrInvalidScannerInput
	}

	scanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &pb.Scanner{
		Id:          scanner.ID.String(),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		Username:    scanner.Username,
		Password:    scanner.Password,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) UpdateScanner(ctx context.Context, req *pb.UpdateScannerRequest) (*pb.Scanner, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, ErrInvalidScannerInput
	}

	// Get existing scanner
	existingScanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update fields
	scanner := *existingScanner
	scanner.Name = req.GetName()
	scanner.Type = domain.ScannerType(req.GetType())
	scanner.Description = req.GetDescription()
	scanner.Endpoint = req.GetEndpoint()
	scanner.Username = req.GetUsername()
	scanner.Password = req.GetPassword()
	scanner.APIKey = req.GetApiKey()
	scanner.Enabled = req.GetEnabled()
	scanner.UpdatedAt = time.Now()

	err = s.service.UpdateScanner(ctx, scanner)
	if err != nil {
		return nil, err
	}

	return &pb.Scanner{
		Id:          scanner.ID.String(),
		Name:        scanner.Name,
		Type:        string(scanner.Type),
		Description: scanner.Description,
		Endpoint:    scanner.Endpoint,
		Username:    scanner.Username,
		Password:    scanner.Password,
		ApiKey:      scanner.APIKey,
		Enabled:     scanner.Enabled,
	}, nil
}

func (s *ScannerService) DeleteScanner(ctx context.Context, req *pb.DeleteScannerRequest) error {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return ErrInvalidScannerInput
	}

	return s.service.DeleteScanner(ctx, id)
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
	for _, s := range scanners {
		pbScanners = append(pbScanners, &pb.Scanner{
			Id:          s.ID.String(),
			Name:        s.Name,
			Type:        string(s.Type),
			Description: s.Description,
			Endpoint:    s.Endpoint,
			Username:    s.Username,
			Password:    s.Password,
			ApiKey:      s.APIKey,
			Enabled:     s.Enabled,
		})
	}

	return &pb.ListScannersResponse{
		Scanners: pbScanners,
	}, nil
}
