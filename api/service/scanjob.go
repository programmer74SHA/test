package service

import (
	"context"
	"errors"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanjobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
)

var (
	ErrScanJobNotFound    = errors.New("scan job not found")
	ErrInvalidScanJobUUID = errors.New("invalid scan job UUID")
	ErrJobNotComplete     = errors.New("scan job is not complete")
)

// ScanJobService provides API operations for scan jobs
type ScanJobService struct {
	service scanjobPort.Service
}

// NewScanJobService creates a new ScanJobService
func NewScanJobService(srv scanjobPort.Service) *ScanJobService {
	return &ScanJobService{service: srv}
}

// GetJobs handles listing of scan jobs with filters, pagination, and sorting
func (s *ScanJobService) GetJobs(ctx context.Context, req *pb.GetJobsRequest) (*pb.GetJobsResponse, error) {
	// Parse filters
	filter := domain.ScanJobFilters{
		Name:   req.GetFilter().GetName(),
		Status: req.GetFilter().GetStatus(),
	}

	// Parse time range
	if f := req.GetFilter().GetStartTimeFrom(); f != "" {
		if t, err := time.Parse(time.RFC3339, f); err == nil {
			filter.StartTimeFrom = &t
		}
	}

	if tStr := req.GetFilter().GetStartTimeTo(); tStr != "" {
		if t, err := time.Parse(time.RFC3339, tStr); err == nil {
			filter.StartTimeTo = &t
		}
	}

	// Pagination
	limit := int(req.GetLimit())
	offset := int(req.GetPage()) * limit

	// Sorting
	sorts := make([]domain.SortOption, len(req.GetSort()))
	for i, srt := range req.GetSort() {
		sorts[i] = domain.SortOption{Field: srt.GetField(), Order: srt.GetOrder()}
	}

	jobs, total, err := s.service.GetJobs(ctx, filter, limit, offset, sorts...)
	if err != nil {
		return nil, err
	}

	// Map to protobuf
	pbJobs := make([]*pb.ScanJob, 0, len(jobs))
	for _, job := range jobs {
		pbJob := &pb.ScanJob{
			Id:        job.ID,
			Name:      job.Name,
			Status:    job.Status,
			StartTime: job.StartTime.Format(time.RFC3339),
			EndTime:   "",
			Progress:  0,
			ScannerId: job.ScannerID,
		}
		if job.EndTime != nil {
			pbJob.EndTime = job.EndTime.Format(time.RFC3339)
		}
		if job.Progress != nil {
			pbJob.Progress = int32(*job.Progress)
		}

		pbJobs = append(pbJobs, pbJob)
	}

	return &pb.GetJobsResponse{Contents: pbJobs, Count: int32(total)}, nil
}

// GetJobByID handles retrieving a scan job by its ID
func (s *ScanJobService) GetJobByID(ctx context.Context, req *pb.GetJobByIDRequest) (*pb.GetJobByIDResponse, error) {
	// Parse UUID
	id := req.GetId()

	job, err := s.service.GetJobByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if job == nil {
		return nil, ErrScanJobNotFound
	}

	// Map to protobuf
	resp := &pb.GetJobByIDResponse{Job: &pb.ScanJob{
		Id:        job.ID,
		Name:      job.Name,
		Status:    job.Status,
		StartTime: job.StartTime.Format(time.RFC3339),
	}}

	// optional fields
	if job.EndTime != nil {
		resp.Job.EndTime = job.EndTime.Format(time.RFC3339)
	}

	if job.Progress != nil {
		resp.Job.Progress = int32(*job.Progress)
	}

	resp.Job.ScannerId = job.ScannerID

	// assets
	for _, as := range job.AssetScanJobs {
		asset := as.Asset
		pbAsset := &pb.Asset{Id: asset.ID.String(), Name: asset.Name, Domain: asset.Domain, Hostname: asset.Hostname, OsName: asset.OSName, OsVersion: asset.OSVersion, Type: asset.Type, Description: asset.Description, CreatedAt: asset.CreatedAt.Format(time.RFC3339), UpdatedAt: asset.UpdatedAt.Format(time.RFC3339), Risk: int32(asset.Risk)}
		resp.Job.AssetScanJobs = append(resp.Job.AssetScanJobs, &pb.AssetScanJob{Asset: pbAsset, DiscoveredAt: as.DiscoveredAt.Format(time.RFC3339)})
	}

	return resp, nil
}

// DiffJobs handles comparing two scan jobs to find new and missing assets
func (s *ScanJobService) DiffJobs(ctx context.Context, req *pb.DiffJobsRequest) (*pb.DiffJobsResponse, error) {
	ids := req.GetIds()

	// Validate that exactly 2 job IDs are provided
	if len(ids) != 2 {
		return nil, errors.New("exactly 2 job IDs must be provided")
	}

	// Get type (new or missing)
	assetType := req.GetType()
	if assetType != "new" && assetType != "missing" {
		return nil, errors.New("type must be 'new' or 'missing'")
	}

	// Get pagination parameters
	limit := int(req.GetLimit())
	page := int(req.GetPage())

	// Default values if not provided
	if limit <= 0 {
		limit = 5
	}
	if page < 0 {
		page = 0
	}

	// Calculate offset from page and limit
	offset := page * limit

	// Get sorting parameters
	sorts := req.GetSort()

	// Call service to get differences
	assets, count, err := s.service.DiffJobsByType(ctx, ids, assetType, limit, offset, sorts)
	if err != nil {
		// Map internal errors to API errors
		switch err.Error() {
		case "newer job is not complete", "older job is not complete":
			return nil, ErrJobNotComplete
		case "scan job not found", "one or both jobs not found":
			return nil, ErrScanJobNotFound
		case "exactly 2 job IDs must be provided":
			return nil, errors.New("exactly 2 job IDs must be provided")
		default:
			return nil, err
		}
	}

	convertAssetDomainToPb := func(asset assetDomain.AssetDomain) *pb.Asset {
		pbPorts := make([]*pb.Port, 0, len(asset.Ports))
		for _, port := range asset.Ports {
			pbPorts = append(pbPorts, &pb.Port{
				Id:             port.ID,
				AssetId:        port.AssetID,
				PortNumber:     int32(port.PortNumber),
				Protocol:       port.Protocol,
				State:          port.State,
				ServiceName:    port.ServiceName,
				ServiceVersion: port.ServiceVersion,
				Description:    port.Description,
				DiscoveredAt:   port.DiscoveredAt.Format(time.RFC3339),
			})
		}

		pbVMwareVMs := make([]*pb.VMwareVM, 0, len(asset.VMwareVMs))
		for _, vm := range asset.VMwareVMs {
			pbVMwareVMs = append(pbVMwareVMs, &pb.VMwareVM{
				VmId:         vm.VMID,
				AssetId:      vm.AssetID,
				VmName:       vm.VMName,
				Hypervisor:   vm.Hypervisor,
				CpuCount:     int32(vm.CPUCount),
				MemoryMb:     int32(vm.MemoryMB),
				DiskSizeGb:   int32(vm.DiskSizeGB),
				PowerState:   vm.PowerState,
				LastSyncedAt: vm.LastSyncedAt.Format(time.RFC3339),
			})
		}

		pbAssetIPs := make([]*pb.AssetIP, 0, len(asset.AssetIPs))
		for _, ip := range asset.AssetIPs {
			pbAssetIPs = append(pbAssetIPs, &pb.AssetIP{
				AssetId:    ip.AssetID,
				Ip:         ip.IP,
				MacAddress: ip.MACAddress,
			})
		}

		return &pb.Asset{
			Id:          asset.ID.String(),
			Name:        asset.Name,
			Domain:      asset.Domain,
			Hostname:    asset.Hostname,
			OsName:      asset.OSName,
			OsVersion:   asset.OSVersion,
			Type:        asset.Type,
			Description: asset.Description,
			Risk:        int32(asset.Risk),
			CreatedAt:   asset.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   asset.UpdatedAt.Format(time.RFC3339),
			Ports:       pbPorts,
			VmwareVms:   pbVMwareVMs,
			AssetIps:    pbAssetIPs,
		}
	}

	pbAssets := make([]*pb.Asset, 0, len(assets))
	for _, asset := range assets {
		pbAssets = append(pbAssets, convertAssetDomainToPb(asset))
	}

	return &pb.DiffJobsResponse{
		Contents: pbAssets,
		Count:    int32(count),
	}, nil
}

// ExportJobDiff exports the differences between two scan jobs as a CSV file
func (s *ScanJobService) ExportJobDiff(ctx context.Context, req *pb.ExportJobDiffRequest) ([]byte, error) {
	ids := req.GetIds()

	// Validate that exactly 2 job IDs are provided
	if len(ids) != 2 {
		return nil, errors.New("exactly 2 job IDs must be provided")
	}

	export_data, err := s.service.ExportDiffJobs(ctx, ids)
	if err != nil {
		return nil, err
	}

	// Get the asset service from the container
	assetSvc := s.service.GetAssetService()

	// Use the asset service's GenerateCSV method
	csvData, err := assetSvc.GenerateCSV(ctx, export_data)
	if err != nil {
		return nil, err
	}

	return csvData, nil
}
