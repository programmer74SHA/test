package storage

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/utils"
	"gorm.io/gorm"
)

// NewAssetRepo creates a new asset repository
func NewAssetRepo(db *gorm.DB) assetPort.Repo {
	return &assetRepository{
		db: db,
	}
}

// assetRepository implements the assetPort.Repo interface
type assetRepository struct {
	db *gorm.DB
}

// UpdateAssetPorts implements port.Repo.
func (r *assetRepository) UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error {
	logger.InfoContext(ctx, "Repository: Updating ports for asset %s, count: %d", assetID.String(), len(ports))

	// Begin a transaction
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Repository: Failed to begin transaction for port update: %v", tx.Error)
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Repository: Panic occurred during port update, rolling back: %v", r)
			tx.Rollback()
		}
	}()

	if err := tx.Table("ports").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		tx.Rollback()
		logger.ErrorContext(ctx, "Repository: Failed to mark existing ports as deleted: %v", err)
		return err
	}
	logger.DebugContext(ctx, "Repository: Marked existing ports as deleted for asset ID: %s", assetID.String())

	for _, port := range ports {
		port.AssetID = assetID.String()
		if err := tx.Create(&port).Error; err != nil {
			tx.Rollback()
			logger.ErrorContext(ctx, "Repository: Failed to create new port for asset %s: %v", assetID.String(), err)
			return err
		}
	}

	logger.DebugContext(ctx, "Repository: Created %d new ports for asset %s", len(ports), assetID.String())

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to commit port update transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Repository: Successfully updated ports for asset %s", assetID.String())
	return nil
}

// Create implements the asset repository Create method without placeholder IPs
func (r *assetRepository) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	logger.InfoContextWithFields(ctx, "Repository: Creating asset", map[string]interface{}{
		"asset_id":      asset.ID.String(),
		"asset_name":    asset.Name,
		"hostname":      asset.Hostname,
		"ip_count":      len(asset.AssetIPs),
		"port_count":    len(asset.Ports),
		"discovered_by": asset.DiscoveredBy,
	})

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Asset{}).
		Where("hostname = ? AND deleted_at IS NULL", asset.Hostname).
		Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to check hostname uniqueness: %v", err)
		return domain.AssetUUID{}, err
	}

	if count > 0 {
		logger.WarnContext(ctx, "Repository: Hostname %s already exists", asset.Hostname)
		return domain.AssetUUID{}, domain.ErrHostnameAlreadyExists
	}

	// Filter and validate IPs while preserving MAC addresses
	var validAssetIPs []domain.AssetIP
	for _, assetIP := range asset.AssetIPs {
		// Basic IP validation
		if r.validateIP(assetIP.IP) {
			validAssetIPs = append(validAssetIPs, domain.AssetIP{
				AssetID:    asset.ID.String(),
				IP:         assetIP.IP,
				MACAddress: assetIP.MACAddress,
			})
		} else {
			logger.DebugContext(ctx, "Repository: Filtering out invalid IP format: %s", assetIP.IP)
		}
	}
	asset.AssetIPs = validAssetIPs

	logger.DebugContext(ctx, "Repository: Validated %d IPs for asset creation", len(validAssetIPs))

	// Create ports for the asset - prepare the port records
	var portRecords []types.Port
	for _, port := range asset.Ports {
		portRecord := mapper.PortDomain2Storage(port)
		portRecord.AssetID = asset.ID.String()
		portRecords = append(portRecords, *portRecord)
	}

	// Convert asset domain to storage model
	assetRecord, assetIPs := mapper.AssetDomain2Storage(asset)

	// Begin transaction
	tx, err := r.beginTransaction(ctx)
	if err != nil {
		return domain.AssetUUID{}, err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check for existing IPs if we have valid IPs
	if len(validAssetIPs) > 0 {
		// Check if any IPs already exist
		err = r.handleExistingIPsWithScanner(ctx, tx, asset, validAssetIPs, assetRecord, assetIPs, portRecords)
		if err != nil {
			tx.Rollback()
			if errors.Is(err, domain.ErrIPAlreadyExists) {
				logger.WarnContext(ctx, "Repository: IP already exists for asset %s: %v", asset.ID, err)
				return uuid.Nil, err
			}
			logger.ErrorContext(ctx, "Repository: Failed to handle existing IPs for asset %s: %v", asset.ID, err)
			return domain.AssetUUID{}, err
		}
	} else {
		// No IPs to check, create a completely new asset
		if err := r.createAssetWithTx(tx, assetRecord); err != nil {
			tx.Rollback()
			logger.ErrorContext(ctx, "Repository: Failed to create new asset without IPs: %v", err)
			return domain.AssetUUID{}, err
		}

		// Create ports for the asset
		if err := r.createPortsWithTx(tx, portRecords, asset.ID.String()); err != nil {
			tx.Rollback()
			logger.ErrorContext(ctx, "Repository: Failed to create ports for asset %s: %v", asset.ID, err)
			return domain.AssetUUID{}, err
		}

		// Create asset IPs
		if len(assetIPs) > 0 {
			if err := r.createNewIPs(tx, assetIPs, make(map[string]bool)); err != nil {
				tx.Rollback()
				logger.ErrorContext(ctx, "Repository: Failed to create asset IPs: %v", err)
				return domain.AssetUUID{}, err
			}
		} else {
			logger.DebugContext(ctx, "Repository: No valid IPs to create for asset %s", asset.ID)
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Error committing transaction: %v", err)
		return domain.AssetUUID{}, err
	}

	logger.InfoContext(ctx, "Repository: Successfully created new asset with ID: %s and %d IPs, discovered by: %s",
		asset.ID, len(asset.AssetIPs), asset.DiscoveredBy)
	return asset.ID, nil
}

// validateIP checks if a string is a valid IP address format
func (r *assetRepository) validateIP(ip string) bool {
	// Skip empty IPs
	if ip == "" {
		logger.Debug("Repository: Empty IP validation - returning false")
		return false
	}

	// Skip obvious hostnames (no dots, contains non-numeric/dot characters)
	if !strings.Contains(ip, ".") {
		logger.Debug("Repository: IP validation failed - no dots found in: %s", ip)
		return false
	}

	// Basic IPv4 validation
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		logger.Debug("Repository: IP validation failed - wrong number of parts (%d) in: %s", len(parts), ip)
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			logger.Debug("Repository: IP validation failed - invalid part '%s' in: %s", part, ip)
			return false
		}
	}

	logger.Debug("Repository: IP validation passed for: %s", ip)
	return true
}

// getAssetIPs retrieves all IPs associated with an asset
func (r *assetRepository) getAssetIPs(ctx context.Context, assetID string) ([]types.AssetIP, error) {
	logger.DebugContext(ctx, "Repository: Getting asset IPs for asset ID: %s", assetID)

	var assetIPs []types.AssetIP
	err := r.db.WithContext(ctx).Table("asset_ips").
		Where("asset_id = ?", assetID).
		Where("deleted_at IS NULL").
		Find(&assetIPs).Error

	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to get asset IPs for asset %s: %v", assetID, err)
		return assetIPs, err
	}

	logger.DebugContext(ctx, "Repository: Retrieved %d IPs for asset %s", len(assetIPs), assetID)
	return assetIPs, err
}

// GetByIDs fetches assets by their UUIDs in a single query
// If a single UUID is provided, it returns a slice with one asset
func (r *assetRepository) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	if len(assetUUIDs) == 0 {
		logger.DebugContext(ctx, "Repository: Empty asset UUIDs list provided")
		return []domain.AssetDomain{}, nil
	}

	logger.InfoContext(ctx, "Repository: Getting assets by IDs (count: %d)", len(assetUUIDs))

	ids := make([]string, len(assetUUIDs))
	for i, uid := range assetUUIDs {
		ids[i] = uid.String()
	}

	var assets []types.Asset
	query := r.db.WithContext(ctx).
		Preload("Ports", "deleted_at IS NULL").
		Preload("VMwareVMs").
		Preload("AssetIPs", "deleted_at IS NULL").
		Where("deleted_at IS NULL")

	if len(assetUUIDs) == 1 {
		logger.DebugContext(ctx, "Repository: Querying single asset by ID: %s", assetUUIDs[0].String())
		err := query.Where("id = ?", assetUUIDs[0]).Find(&assets).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to get asset by ID %s: %v", assetUUIDs[0].String(), err)
			return nil, err
		}
	} else {
		logger.DebugContext(ctx, "Repository: Querying multiple assets by IDs (count: %d)", len(assetUUIDs))
		err := query.Where("id IN ?", ids).Find(&assets).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to get assets by IDs: %v", err)
			return nil, err
		}
	}

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	logger.DebugContext(ctx, "Repository: Retrieved %d assets from database", len(assets))

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	result := make([]domain.AssetDomain, 0, len(assets))
	for _, a := range assets {

		scannerType := scannerTypeMap[a.ID]

		dom, err := mapper.AssetStorage2DomainWithScannerType(a, scannerType)
		if err != nil {
			logger.WarnContext(ctx, "Repository: Failed to convert asset %s to domain: %v", a.ID, err)
			continue
		}
		result = append(result, *dom)
	}

	logger.InfoContext(ctx, "Repository: Successfully retrieved and converted %d assets", len(result))
	return result, nil
}

// GetByIDsWithSort fetches assets by their UUIDs with sorting applied at the database level
func (r *assetRepository) GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error) {
	if len(assetUUIDs) == 0 {
		logger.DebugContext(ctx, "Repository: Empty asset UUIDs list provided for sorted query")
		return []domain.AssetDomain{}, nil
	}

	logger.InfoContextWithFields(ctx, "Repository: Getting assets by IDs with sort", map[string]interface{}{
		"asset_count": len(assetUUIDs),
		"sort_count":  len(sortOptions),
	})

	ids := make([]string, len(assetUUIDs))
	for i, uid := range assetUUIDs {
		ids[i] = uid.String()
	}

	query := r.db.WithContext(ctx).Table("assets").
		Preload("Ports", "deleted_at IS NULL").
		Preload("VMwareVMs").
		Preload("AssetIPs", "deleted_at IS NULL").
		Where("assets.deleted_at IS NULL")

	// Apply ID filter
	if len(assetUUIDs) == 1 {
		logger.DebugContext(ctx, "Repository: Querying single asset with sort: %s", assetUUIDs[0].String())
		query = query.Where("assets.id = ?", assetUUIDs[0])
	} else {
		logger.DebugContext(ctx, "Repository: Querying multiple assets with sort (count: %d)", len(assetUUIDs))
		query = query.Where("assets.id IN ?", ids)
	}

	// Apply sorting if provided
	appliedJoins := make(map[string]bool)
	if len(sortOptions) > 0 {
		logger.DebugContext(ctx, "Repository: Applying %d sort options to query", len(sortOptions))
		for _, sort := range sortOptions {
			columnMapping := mapFieldToDBColumn(sort.Field)

			if columnMapping.RequiresJoin && !appliedJoins[columnMapping.Table] {
				query = query.Joins(columnMapping.JoinQuery)
				appliedJoins[columnMapping.Table] = true
			}

			orderDir := "ASC"
			if sort.Order == "desc" {
				orderDir = "DESC"
			}

			if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
				if orderDir == "ASC" {
					query = query.Order("MIN(" + columnMapping.Column + ") " + orderDir)
				} else {
					query = query.Order("MAX(" + columnMapping.Column + ") " + orderDir)
				}
				// Group by assets.id to handle multiple related records
				query = query.Group("assets.id")
			} else {
				query = query.Order(columnMapping.Column + " " + orderDir)
			}
		}
	}

	var assets []types.Asset
	err := query.Find(&assets).Error
	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to execute sorted query for assets: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "Repository: Retrieved %d assets from sorted query", len(assets))

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	result := make([]domain.AssetDomain, 0, len(assets))
	for _, a := range assets {
		scannerType := scannerTypeMap[a.ID]

		dom, err := mapper.AssetStorage2DomainWithScannerType(a, scannerType)
		if err != nil {
			logger.WarnContext(ctx, "Repository: Failed to convert sorted asset %s to domain: %v", a.ID, err)
			continue
		}
		result = append(result, *dom)
	}

	logger.InfoContext(ctx, "Repository: Successfully retrieved and converted %d sorted assets", len(result))
	return result, nil
}

// Get retrieves assets based on filters
func (r *assetRepository) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	logger.InfoContextWithFields(ctx, "Repository: Getting assets with filters", map[string]interface{}{
		"has_name_filter":     assetFilter.Name != "",
		"has_hostname_filter": assetFilter.Hostname != "",
		"has_ip_filter":       assetFilter.IP != "",
		"has_type_filter":     assetFilter.Type != "",
	})

	query := r.db.WithContext(ctx).Table("assets").Where("assets.deleted_at IS NULL")

	// Apply filters
	if assetFilter.Name != "" {
		logger.DebugContext(ctx, "Repository: Applying name filter: %s", assetFilter.Name)
		query = query.Where("name LIKE ?", "%"+assetFilter.Name+"%")
	}
	if assetFilter.Domain != "" {
		logger.DebugContext(ctx, "Repository: Applying domain filter: %s", assetFilter.Domain)
		query = query.Where("domain LIKE ?", "%"+assetFilter.Domain+"%")
	}
	if assetFilter.Hostname != "" {
		logger.DebugContext(ctx, "Repository: Applying hostname filter: %s", assetFilter.Hostname)
		query = query.Where("hostname LIKE ?", "%"+assetFilter.Hostname+"%")
	}
	if assetFilter.OSName != "" {
		logger.DebugContext(ctx, "Repository: Applying OS name filter: %s", assetFilter.OSName)
		query = query.Where("os_name LIKE ?", "%"+assetFilter.OSName+"%")
	}
	if assetFilter.OSVersion != "" {
		logger.DebugContext(ctx, "Repository: Applying OS version filter: %s", assetFilter.OSVersion)
		query = query.Where("os_version LIKE ?", "%"+assetFilter.OSVersion+"%")
	}
	if assetFilter.Type != "" {
		logger.DebugContext(ctx, "Repository: Applying asset type filter: %s", assetFilter.Type)
		query = query.Where("asset_type = ?", assetFilter.Type)
	}

	// Handle IP filter specially - need to join with asset_ips table
	if assetFilter.IP != "" {
		logger.DebugContext(ctx, "Repository: Applying IP filter with join: %s", assetFilter.IP)
		// Join with asset_ips and filter by IP
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+assetFilter.IP+"%")
	}

	var assets []types.Asset
	if err := query.Find(&assets).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to execute filtered query: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "Repository: Retrieved %d assets from filtered query", len(assets))

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	// Convert to domain models
	var domainResults []domain.AssetDomain
	for _, asset := range assets {
		// Get IPs for this asset
		_, err := r.getAssetIPs(ctx, asset.ID)
		if err != nil {
			logger.WarnContext(ctx, "Repository: Failed to get IPs for asset %s during filtering: %v", asset.ID, err)
			continue
		}

		scannerType := scannerTypeMap[asset.ID]

		// Convert to domain model with scanner type
		assetDomain, err := mapper.AssetStorage2DomainWithScannerType(asset, scannerType)
		if err != nil {
			logger.WarnContext(ctx, "Repository: Failed to convert filtered asset %s to domain: %v", asset.ID, err)
			continue
		}

		domainResults = append(domainResults, *assetDomain)
	}

	logger.InfoContext(ctx, "Repository: Successfully retrieved and converted %d filtered assets", len(domainResults))
	return domainResults, nil
}

// Get implements the asset repository Get method with filtering, sorting, and pagination
func (r *assetRepository) GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	logger.InfoContextWithFields(ctx, "Repository: Getting assets by filter with pagination", map[string]interface{}{
		"limit":               limit,
		"offset":              offset,
		"sort_count":          len(sortOptions),
		"has_name_filter":     assetFilter.Name != "",
		"has_hostname_filter": assetFilter.Hostname != "",
		"has_ip_filter":       assetFilter.IP != "",
	})

	var assets []types.Asset
	var total int64

	// Create base query without table() to allow preloading
	query := r.db.WithContext(ctx).Model(&types.Asset{})
	query = applyAssetFilters(r.db, query, assetFilter)

	query = query.Where("assets.deleted_at IS NULL")

	countQuery := r.db.WithContext(ctx).Model(&types.Asset{})
	countQuery = applyAssetFilters(r.db, countQuery, assetFilter)
	countQuery = countQuery.Where("assets.deleted_at IS NULL")

	// Check if any sort options require joins that would affect count
	requiresDistinctCount := false
	for _, sort := range sortOptions {
		columnMapping := mapFieldToDBColumn(sort.Field)
		if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
			requiresDistinctCount = true
			break
		}
	}

	logger.DebugContext(ctx, "Repository: Requires distinct count: %v", requiresDistinctCount)

	if requiresDistinctCount {
		err := countQuery.Select("DISTINCT assets.id").Count(&total).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to get distinct count for filtered assets: %v", err)
			return nil, 0, err
		}
	} else {
		err := countQuery.Count(&total).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to get count for filtered assets: %v", err)
			return nil, 0, err
		}
	}

	logger.DebugContext(ctx, "Repository: Total assets found: %d", total)

	// Apply sorting if provided
	appliedJoins := make(map[string]bool)
	if len(sortOptions) > 0 {
		logger.DebugContext(ctx, "Repository: Applying %d sort options", len(sortOptions))
		for _, sort := range sortOptions {
			columnMapping := mapFieldToDBColumn(sort.Field)

			if columnMapping.RequiresJoin && !appliedJoins[columnMapping.Table] {
				query = query.Joins(columnMapping.JoinQuery)
				appliedJoins[columnMapping.Table] = true
				logger.DebugContext(ctx, "Repository: Applied join for table: %s", columnMapping.Table)
			}

			orderDir := "ASC"
			if sort.Order == "desc" {
				orderDir = "DESC"
			}

			if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
				// Use MIN/MAX to handle multiple related records for consistent sorting
				// This ensures deterministic results when an asset has multiple IPs, VMs, or scan jobs
				if orderDir == "ASC" {
					query = query.Order("MIN(" + columnMapping.Column + ") " + orderDir)
				} else {
					query = query.Order("MAX(" + columnMapping.Column + ") " + orderDir)
				}
				// Group by assets.id to handle multiple related records
				query = query.Group("assets.id")
				logger.DebugContext(ctx, "Repository: Applied MIN/MAX sort with GROUP BY for field: %s", sort.Field)
			} else {
				query = query.Order(columnMapping.Column + " " + orderDir)
				logger.DebugContext(ctx, "Repository: Applied regular sort for field: %s", sort.Field)
			}
		}
	}

	hasGroupBy := false
	for _, sort := range sortOptions {
		columnMapping := mapFieldToDBColumn(sort.Field)
		if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
			hasGroupBy = true
			break
		}
	}

	logger.DebugContext(ctx, "Repository: Query has GROUP BY: %v", hasGroupBy)

	if hasGroupBy {
		query = query.Select("assets.*")
	} else {
		query = query.Preload("Ports", "deleted_at IS NULL").Preload("VMwareVMs").Preload("AssetIPs", "deleted_at IS NULL")
	}

	// Apply pagination only when limits are set
	if limit > 0 {
		query = query.Limit(limit)
		logger.DebugContext(ctx, "Repository: Applied limit: %d", limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
		logger.DebugContext(ctx, "Repository: Applied offset: %d", offset)
	}

	err := query.Find(&assets).Error
	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to execute filtered query with pagination: %v", err)
		return nil, 0, err
	}

	logger.DebugContext(ctx, "Repository: Retrieved %d assets from paginated query", len(assets))

	// If we had GROUP BY, we need to manually load related data for the assets
	if hasGroupBy && len(assets) > 0 {
		logger.DebugContext(ctx, "Repository: Loading related data separately due to GROUP BY")
		assetIDs := make([]string, len(assets))
		for i, asset := range assets {
			assetIDs[i] = asset.ID
		}

		// Load ports separately
		var ports []types.Port
		err = r.db.WithContext(ctx).Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).Find(&ports).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to load ports for grouped assets: %v", err)
			return nil, 0, err
		}
		logger.DebugContext(ctx, "Repository: Loaded %d ports for %d assets", len(ports), len(assetIDs))

		// Load VMware VMs separately
		var vmwares []types.VMwareVM
		err = r.db.WithContext(ctx).Where("asset_id IN ?", assetIDs).Find(&vmwares).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to load VMware VMs for grouped assets: %v", err)
			return nil, 0, err
		}
		logger.DebugContext(ctx, "Repository: Loaded %d VMware VMs for %d assets", len(vmwares), len(assetIDs))

		// Load asset IPs separately
		var assetIPs []types.AssetIP
		err = r.db.WithContext(ctx).Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).Find(&assetIPs).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to load asset IPs for grouped assets: %v", err)
			return nil, 0, err
		}
		logger.DebugContext(ctx, "Repository: Loaded %d asset IPs for %d assets", len(assetIPs), len(assetIDs))

		// Map the related data back to assets
		portMap := make(map[string][]types.Port)
		for _, port := range ports {
			portMap[port.AssetID] = append(portMap[port.AssetID], port)
		}

		vmwareMap := make(map[string][]types.VMwareVM)
		for _, vm := range vmwares {
			vmwareMap[vm.AssetID] = append(vmwareMap[vm.AssetID], vm)
		}

		ipMap := make(map[string][]types.AssetIP)
		for _, ip := range assetIPs {
			ipMap[ip.AssetID] = append(ipMap[ip.AssetID], ip)
		}

		// Assign the related data to assets
		for i := range assets {
			assets[i].Ports = portMap[assets[i].ID]
			assets[i].VMwareVMs = vmwareMap[assets[i].ID]
			assets[i].AssetIPs = ipMap[assets[i].ID]
		}
		logger.DebugContext(ctx, "Repository: Mapped related data back to assets")
	}

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	// Process the assets with their preloaded relationships
	result := make([]domain.AssetDomain, 0, len(assets))
	for _, asset := range assets {
		scannerType := scannerTypeMap[asset.ID]

		domainAsset, err := mapper.AssetStorage2DomainWithScannerType(asset, scannerType)
		if err != nil {
			logger.WarnContext(ctx, "Repository: Failed to convert paginated asset %s to domain: %v", asset.ID, err)
			// Skip this asset if mapping fails
			continue
		}
		result = append(result, *domainAsset)
	}

	logger.InfoContext(ctx, "Repository: Successfully retrieved %d paginated assets (total: %d)", len(result), total)
	return result, int(total), nil
}

// Update updates an existing asset along with its ports and IPs
func (r *assetRepository) Update(ctx context.Context, asset domain.AssetDomain) error {
	logger.InfoContextWithFields(ctx, "Repository: Updating asset", map[string]interface{}{
		"asset_id":   asset.ID.String(),
		"asset_name": asset.Name,
		"hostname":   asset.Hostname,
		"port_count": len(asset.Ports),
		"ip_count":   len(asset.AssetIPs),
	})

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Asset{}).
		Where("hostname = ? AND id != ? AND deleted_at IS NULL", asset.Hostname, asset.ID.String()).
		Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to check hostname uniqueness during update: %v", err)
		return err
	}

	if count > 0 {
		logger.WarnContext(ctx, "Repository: Hostname %s already exists for another asset", asset.Hostname)
		return domain.ErrHostnameAlreadyExists
	}

	// Filter and validate IPs while preserving MAC addresses
	var validAssetIPs []domain.AssetIP
	for i, assetIP := range asset.AssetIPs {
		logger.DebugContext(ctx, "Repository: Processing asset IP %d: %s with MAC: %s", i, assetIP.IP, assetIP.MACAddress)
		// Basic IP validation
		if r.validateIP(assetIP.IP) {
			validAssetIPs = append(validAssetIPs, domain.AssetIP{
				AssetID:    asset.ID.String(),
				IP:         assetIP.IP,
				MACAddress: assetIP.MACAddress,
			})
		} else {
			logger.DebugContext(ctx, "Repository: Filtering out invalid IP format: %s", assetIP.IP)
		}
	}
	asset.AssetIPs = validAssetIPs

	logger.DebugContext(ctx, "Repository: Validated %d IPs for asset update", len(validAssetIPs))

	a, assetIPPtrs := mapper.AssetDomain2Storage(asset)

	// Begin a transaction
	tx, err := r.beginTransaction(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to begin transaction for asset update: %v", err)
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Get current IPs for this asset
	var currentIPs []types.AssetIP
	if err := tx.Table("asset_ips").
		Where("asset_id = ? AND deleted_at IS NULL", asset.ID.String()).
		Find(&currentIPs).Error; err != nil {
		tx.Rollback()
		logger.ErrorContext(ctx, "Repository: Failed to get current active IPs for asset %s: %v", asset.ID.String(), err)
		return err
	}

	logger.InfoContext(ctx, "Found %d current active IPs for asset %s", len(currentIPs), asset.ID.String())

	currentIPMap := make(map[string]types.AssetIP)
	for _, ip := range currentIPs {
		currentIPMap[ip.IPAddress] = ip
		logger.InfoContext(ctx, "Current active IP: %s with ID: %s", ip.IPAddress, ip.ID)
	}

	newIPMap := make(map[string]bool)
	for _, ip := range validAssetIPs {
		newIPMap[ip.IP] = true
		logger.InfoContext(ctx, "New IP from request: %s", ip.IP)
	}

	// Identify IPs that need to be marked as deleted (they exist in current but not in new)
	var ipsToDelete []types.AssetIP
	for ipAddr, assetIP := range currentIPMap {
		if _, exists := newIPMap[ipAddr]; !exists {
			ipsToDelete = append(ipsToDelete, assetIP)
			logger.InfoContext(ctx, "Marking IP for deletion: %s with ID: %s", ipAddr, assetIP.ID)
		}
	}

	// Identify new IPs that need to be added (they exist in new but not in current)
	var ipsToAdd []domain.AssetIP
	for _, assetIP := range validAssetIPs {
		if _, exists := currentIPMap[assetIP.IP]; !exists {
			ipsToAdd = append(ipsToAdd, assetIP)
			logger.InfoContext(ctx, "Marking IP for addition: %s", assetIP.IP)
		}
	}

	// Check if any IP changes are needed
	ipsChanged := len(ipsToDelete) > 0 || len(ipsToAdd) > 0

	if ipsChanged {
		logger.InfoContext(ctx, "IPs have changed, processing IP changes (delete: %d, add: %d)", len(ipsToDelete), len(ipsToAdd))

		if len(ipsToDelete) > 0 {
			var idsToDelete []string
			for _, ip := range ipsToDelete {
				idsToDelete = append(idsToDelete, ip.ID)
				logger.InfoContext(ctx, "Marking IP %s as deleted for asset %s", ip.IPAddress, asset.ID.String())
			}

			if err := tx.Table("asset_ips").
				Where("id IN ?", idsToDelete).
				Update("deleted_at", time.Now()).Error; err != nil {
				tx.Rollback()
				logger.InfoContext(ctx, "Error marking IPs as deleted: %v", err)
				return err
			}
			logger.InfoContext(ctx, "Marked %d existing IPs as deleted for asset ID: %s", len(ipsToDelete), asset.ID)
		}

		// Only process new IPs if there are any to add
		if len(ipsToAdd) > 0 {
			var newIPAddresses []string
			for _, ip := range ipsToAdd {
				newIPAddresses = append(newIPAddresses, ip.IP)
			}

			// Find any existing IPs in the database (both active and deleted)
			existingActiveIPs, existingDeletedIPs, err := r.findExistingIPs(ctx, newIPAddresses)
			if err != nil {
				tx.Rollback()
				logger.ErrorContext(ctx, "Repository: Failed to find existing IPs for asset %s: %v", asset.ID.String(), err)
				return err
			}

			// Filter out active IPs that belong to other assets
			var conflictActiveIPs []types.AssetIP
			for _, ip := range existingActiveIPs {
				if ip.AssetID != asset.ID.String() {
					conflictActiveIPs = append(conflictActiveIPs, ip)
				}
			}

			// Check for conflicts with other assets' active IPs
			if len(conflictActiveIPs) > 0 {
				isConflict, err := r.checkActiveIPsAssets(ctx, conflictActiveIPs)
				if err != nil {
					tx.Rollback()
					logger.ErrorContext(ctx, "Repository: Error checking active IPs for conflicts: %v", err)
					return err
				}
				if isConflict {
					tx.Rollback()
					logger.WarnContext(ctx, "Repository: IPs already exist for another asset, cannot add new IPs")
					return domain.ErrIPAlreadyExists
				}
			}

			// Process deleted IPs that can be undeleted
			processedIPs := make(map[string]bool)

			// Undelete and reassign any deleted IPs
			for _, deletedIP := range existingDeletedIPs {
				processedIPs[deletedIP.IPAddress] = true
				macAddress := r.findMACForIP(deletedIP.IPAddress, validAssetIPs)
				logger.InfoContext(ctx, "Undeleting IP %s and assigning to asset %s", deletedIP.IPAddress, asset.ID.String())

				if err := r.updateOrUndeleteIP(tx, deletedIP, asset.ID.String(), macAddress); err != nil {
					tx.Rollback()
					logger.ErrorContext(ctx, "Error unDeleting IP %s: %v", deletedIP.IPAddress, err)
					return err
				}
			}

			// Filter out IPs that were already processed (undeleted) or already belong to this asset
			var newIPsToCreate []*types.AssetIP
			for _, ipPtr := range assetIPPtrs {
				if ipPtr == nil {
					continue
				}

				// Skip IPs that are already processed or already belong to this asset
				if processedIPs[ipPtr.IPAddress] || currentIPMap[ipPtr.IPAddress].ID != "" {
					continue
				}

				newIPsToCreate = append(newIPsToCreate, ipPtr)
			}

			// Create only truly new IPs (not already existing for any asset)
			if len(newIPsToCreate) > 0 {
				for _, ipPtr := range newIPsToCreate {
					logger.InfoContext(ctx, "Creating new IP %s for asset %s", ipPtr.IPAddress, asset.ID.String())
					if err := tx.Table("asset_ips").Create(ipPtr).Error; err != nil {
						tx.Rollback()
						logger.WarnContext(ctx, "Error creating new IP %s: %v", ipPtr.IPAddress, err)
						return err
					}
				}
			}
		}
	} else {
		logger.InfoContext(ctx, "IPs have not changed, skipping IP processing")
	}

	// Update MAC addresses for existing IPs that remain unchanged
	for _, assetIP := range validAssetIPs {
		if currentIP, exists := currentIPMap[assetIP.IP]; exists {
			// Check if MAC address needs to be updated
			if assetIP.MACAddress != "" && assetIP.MACAddress != currentIP.MACAddress {
				logger.InfoContext(ctx, "Updating MAC address for IP %s from %s to %s", assetIP.IP, currentIP.MACAddress, assetIP.MACAddress)
				updates := map[string]interface{}{
					"mac_address": assetIP.MACAddress,
					"updated_at":  time.Now(),
				}
				if err := tx.Table("asset_ips").
					Where("id = ?", currentIP.ID).
					Updates(updates).Error; err != nil {
					tx.Rollback()
					logger.WarnContext(ctx, "Error updating MAC address for IP %s: %v", assetIP.IP, err)
					return err
				}
			}
		}
	}

	// Update the asset record
	if err := tx.Table("assets").
		Where("id = ?", a.ID).
		Updates(a).Error; err != nil {
		tx.Rollback()
		logger.WarnContext(ctx, "Error updating asset record: %v", err)
		return err
	}
	logger.InfoContext(ctx, "Successfully updated asset record for ID: %s", a.ID)

	var currentPorts []types.Port
	if err := tx.Table("ports").
		Where("asset_id = ? AND deleted_at IS NULL", a.ID).
		Find(&currentPorts).Error; err != nil {
		tx.Rollback()
		logger.WarnContext(ctx, "Error getting current ports: %v", err)
		return err
	}
	logger.InfoContext(ctx, "Found %d current active ports for asset %s", len(currentPorts), a.ID)

	// If no ports in the update, mark all existing ports as deleted
	if len(asset.Ports) == 0 {
		if len(currentPorts) > 0 {
			// Soft delete all existing ports
			if err := tx.Table("ports").
				Where("asset_id = ? AND deleted_at IS NULL", a.ID).
				Update("deleted_at", time.Now()).Error; err != nil {
				tx.Rollback()
				logger.WarnContext(ctx, "Error marking ports as deleted: %v", err)
				return err
			}
			logger.InfoContext(ctx, "Marked all existing ports as deleted for asset ID: %s", a.ID)
		}
	} else {
		updatePortIDs := make(map[string]bool)
		for _, port := range asset.Ports {
			if port.ID != "" {
				updatePortIDs[port.ID] = true
			}
		}

		if len(currentPorts) > 0 {
			if len(updatePortIDs) > 0 {
				var idsToKeep []string
				for id := range updatePortIDs {
					idsToKeep = append(idsToKeep, id)
				}

				if err := tx.Table("ports").
					Where("asset_id = ? AND deleted_at IS NULL AND id NOT IN ?", a.ID, idsToKeep).
					Update("deleted_at", time.Now()).Error; err != nil {
					tx.Rollback()
					logger.WarnContext(ctx, "Error marking ports as deleted: %v", err)
					return err
				}
				logger.InfoContext(ctx, "Marked ports not in update list as deleted for asset ID: %s", a.ID)
			} else {
				if err := tx.Table("ports").
					Where("asset_id = ? AND deleted_at IS NULL", a.ID).
					Update("deleted_at", time.Now()).Error; err != nil {
					tx.Rollback()
					logger.WarnContext(ctx, "Error marking existing ports as deleted: %v", err)
					return err
				}
				logger.InfoContext(ctx, "No port IDs provided, marked all existing ports as deleted for asset ID: %s", a.ID)
			}
		}

		for _, port := range asset.Ports {
			portRecord := mapper.PortDomain2Storage(port)
			portRecord.AssetID = a.ID

			if portRecord.ID != "" {
				var existingPort types.Port
				result := tx.Where("id = ? AND asset_id = ?", portRecord.ID, a.ID).First(&existingPort)

				if result.Error == nil {

					if result := tx.Model(&existingPort).Updates(port); result.Error != nil {
						tx.Rollback()
						logger.WarnContext(ctx, "Error updating port: %v", result.Error)
						return result.Error
					}
					logger.InfoContext(ctx, "Updated existing port ID: %s for asset ID: %s", portRecord.ID, a.ID)
				} else if result.Error == gorm.ErrRecordNotFound {
					if err := tx.Create(portRecord).Error; err != nil {
						tx.Rollback()
						logger.WarnContext(ctx, "Error creating port: %v", err)
						return err
					}
					logger.InfoContext(ctx, "Port ID provided but not found, created new port with ID: %s for asset ID: %s", portRecord.ID, a.ID)
				} else {
					tx.Rollback()
					logger.WarnContext(ctx, "Error checking if port exists: %v", result.Error)
					return result.Error
				}
			} else {
				portRecord.ID = uuid.New().String()
				if err := tx.Create(portRecord).Error; err != nil {
					tx.Rollback()
					logger.WarnContext(ctx, "Error creating new port: %v", err)
					return err
				}
				logger.InfoContext(ctx, "Created new port with ID: %s for asset ID: %s", portRecord.ID, a.ID)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		logger.WarnContext(ctx, "Error committing transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Successfully updated asset %s with all associated data", asset.ID)
	return nil
}

// LinkAssetToScanJob links an asset to a scan job record
func (r *assetRepository) LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error {
	logger.InfoContext(ctx, "Repository: Linking asset %s to scan job %d", assetID.String(), scanJobID)

	// Create an AssetScanJob record
	assetScanJob := types.AssetScanJob{
		AssetID:      assetID.String(),
		ScanJobID:    scanJobID,
		DiscoveredAt: time.Now(),
	}

	logger.DebugContext(ctx, "Repository: Creating asset-scan job link record")

	// Insert the record
	err := r.db.WithContext(ctx).Table("asset_scan_jobs").Create(&assetScanJob).Error
	if err != nil {
		// Check if it's a duplicate entry error (asset already linked to this scan job)
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "Duplicate entry") {
			logger.WarnContext(ctx, "Repository: Asset %s already linked to scan job %d", assetID.String(), scanJobID)
			return nil
		}
		logger.ErrorContext(ctx, "Repository: Error linking asset to scan job: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Repository: Successfully linked asset %s to scan job %d", assetID.String(), scanJobID)
	return nil
}

// StoreVMwareVM stores VMware VM data in the database
func (r *assetRepository) StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error {
	logger.InfoContextWithFields(ctx, "Repository: Storing VMware VM data", map[string]interface{}{
		"vm_id":       vmData.VMID,
		"vm_name":     vmData.VMName,
		"asset_id":    vmData.AssetID,
		"hypervisor":  vmData.Hypervisor,
		"cpu_count":   vmData.CPUCount,
		"memory_mb":   vmData.MemoryMB,
		"power_state": vmData.PowerState,
	})

	// Convert domain VMwareVM to storage VMwareVM
	storageVM := types.VMwareVM{
		VMID:         vmData.VMID,
		AssetID:      vmData.AssetID,
		VMName:       vmData.VMName,
		Hypervisor:   vmData.Hypervisor,
		CPUCount:     vmData.CPUCount,
		MemoryMB:     vmData.MemoryMB,
		DiskSizeGB:   vmData.DiskSizeGB,
		PowerState:   vmData.PowerState,
		LastSyncedAt: vmData.LastSyncedAt,
	}

	// Check if VM already exists
	var count int64
	if err := r.db.WithContext(ctx).Table("vmware_vms").Where("vm_id = ?", vmData.VMID).Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Error checking if VM exists: %v", err)
		return err
	}

	logger.DebugContext(ctx, "Repository: VM existence check - found %d existing records", count)

	// Insert or update based on existence
	if count > 0 {
		// Update existing record
		logger.InfoContext(ctx, "Repository: Updating existing VM record for %s", vmData.VMName)
		err := r.db.WithContext(ctx).Table("vmware_vms").
			Where("vm_id = ?", vmData.VMID).
			Updates(map[string]interface{}{
				"asset_id":       vmData.AssetID,
				"vm_name":        vmData.VMName,
				"hypervisor":     vmData.Hypervisor,
				"cpu_count":      int(vmData.CPUCount),
				"memory_mb":      int(vmData.MemoryMB),
				"disk_size_gb":   vmData.DiskSizeGB,
				"power_state":    vmData.PowerState,
				"last_synced_at": vmData.LastSyncedAt,
			}).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to update VMware VM record: %v", err)
			return err
		}
		logger.InfoContext(ctx, "Repository: Successfully updated VMware VM record for %s", vmData.VMName)
	} else {
		// Insert new record
		logger.InfoContext(ctx, "Repository: Creating new VM record for %s", vmData.VMName)
		err := r.db.WithContext(ctx).Table("vmware_vms").Create(&storageVM).Error
		if err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to create VMware VM record: %v", err)
			return err
		}
		logger.InfoContext(ctx, "Repository: Successfully created new VMware VM record for %s", vmData.VMName)
	}

	return nil
}

// applyAssetFiltersToQuery applies filter conditions to a query
func applyAssetFiltersToQuery(query *gorm.DB, filters *domain.AssetFilters) *gorm.DB {
	logger.Debug("Repository: Applying asset filters to query")

	if filters == nil {
		logger.Debug("Repository: No filters provided, returning unmodified query")
		return query
	}

	if filters.Name != "" {
		query = query.Where("name LIKE ?", "%"+filters.Name+"%")
		logger.Debug("Repository: Applied name filter: %s", filters.Name)
	}
	if filters.Domain != "" {
		query = query.Where("domain LIKE ?", "%"+filters.Domain+"%")
		logger.Debug("Repository: Applied domain filter: %s", filters.Domain)
	}
	if filters.Hostname != "" {
		query = query.Where("hostname LIKE ?", "%"+filters.Hostname+"%")
		logger.Debug("Repository: Applied hostname filter: %s", filters.Hostname)
	}
	if filters.OSName != "" {
		query = query.Where("os_name LIKE ?", "%"+filters.OSName+"%")
		logger.Debug("Repository: Applied OS name filter: %s", filters.OSName)
	}
	if filters.OSVersion != "" {
		query = query.Where("os_version LIKE ?", "%"+filters.OSVersion+"%")
		logger.Debug("Repository: Applied OS version filter: %s", filters.OSVersion)
	}
	if filters.Type != "" {
		query = query.Where("type = ?", filters.Type)
		logger.Debug("Repository: Applied type filter: %s", filters.Type)
	}
	if filters.IP != "" {
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+filters.IP+"%").
			Group("assets.id")
		logger.Debug("Repository: Applied IP filter with join: %s", filters.IP)
	}

	logger.Debug("Repository: Completed applying asset filters to query")
	return query
}

// applyUUIDCondition applies UUID-based conditions to a query based on exclude flag
func applyUUIDCondition(query *gorm.DB, uuids []domain.AssetUUID, exclude bool) *gorm.DB {
	if len(uuids) == 0 {
		logger.Debug("Repository: No UUIDs provided for condition, returning unmodified query")
		return query
	}

	logger.Debug("Repository: Applying UUID condition with %d UUIDs (exclude: %v)", len(uuids), exclude)

	if exclude {
		result := query.Where("assets.id NOT IN ?", uuids)
		logger.Debug("Repository: Applied UUID exclusion condition")
		return result
	}

	result := query.Where("assets.id IN ?", uuids)
	logger.Debug("Repository: Applied UUID inclusion condition")
	return result
}

// DeleteAssets is a unified method that handles all asset deletion scenarios
func (r *assetRepository) DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error) {
	logger.InfoContextWithFields(ctx, "Repository: Deleting assets", map[string]interface{}{
		"has_single_uuid": params.UUID != nil,
		"uuid_count":      len(params.UUIDs),
		"exclude":         params.Exclude,
		"has_filters":     params.Filters != nil,
	})

	currentTime := time.Now()
	query := r.db.WithContext(ctx).Model(&types.Asset{})

	// Always only delete non-deleted assets
	query = query.Where("deleted_at IS NULL")

	// Case 1: Single asset deletion by UUID
	if params.UUID != nil {
		logger.InfoContext(ctx, "Repository: Deleting single asset by UUID: %s", params.UUID.String())
		result := query.Where("id = ?", *params.UUID).
			Update("deleted_at", currentTime)

		if result.Error != nil {
			logger.ErrorContext(ctx, "Repository: Failed to delete single asset: %v", result.Error)
			return 0, result.Error
		}

		deletedCount := int(result.RowsAffected)
		logger.InfoContext(ctx, "Repository: Successfully deleted %d asset(s) by single UUID", deletedCount)
		return deletedCount, nil
	}

	// Use transaction for all other cases to ensure atomicity
	var affectedRows int64
	logger.DebugContext(ctx, "Repository: Starting transaction for bulk asset deletion")

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txQuery := tx.Model(&types.Asset{}).Where("deleted_at IS NULL")

		// Apply filters if they exist
		if params.Filters != nil {
			logger.DebugContext(ctx, "Repository: Applying filters to deletion query")
			txQuery = applyAssetFilters(tx, txQuery, *params.Filters)
		}

		// Apply UUID conditions if UUIDs exist
		if len(params.UUIDs) > 0 {
			logger.DebugContext(ctx, "Repository: Applying UUID conditions to deletion query")
			txQuery = applyUUIDCondition(txQuery, params.UUIDs, params.Exclude)
		}

		result := txQuery.Update("deleted_at", currentTime)
		if result.Error != nil {
			logger.ErrorContext(ctx, "Repository: Failed to execute bulk deletion: %v", result.Error)
			return result.Error
		}

		affectedRows = result.RowsAffected
		logger.DebugContext(ctx, "Repository: Bulk deletion affected %d rows", affectedRows)
		return nil
	})

	if err != nil {
		logger.ErrorContext(ctx, "Repository: Transaction failed for asset deletion: %v", err)
		return 0, err
	}

	deletedCount := int(affectedRows)
	logger.InfoContext(ctx, "Repository: Successfully deleted %d asset(s) in bulk operation", deletedCount)
	return deletedCount, nil
}

// ExportAssets exports assets based on asset IDs and export type
func (r *assetRepository) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	logger.InfoContextWithFields(ctx, "Repository: Exporting assets", map[string]interface{}{
		"asset_count":      len(assetIDs),
		"export_type":      int(exportType),
		"selected_columns": len(selectedColumns),
		"fetch_all":        len(assetIDs) == 0,
	})

	exportData := &domain.ExportData{
		Assets:    make([]map[string]interface{}, 0),
		Ports:     make([]map[string]interface{}, 0),
		VMwareVMs: make([]map[string]interface{}, 0),
		AssetIPs:  make([]map[string]interface{}, 0),
	}

	stringIDs := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		stringIDs[i] = id.String()
	}

	// Check if it's "All" assets request
	fetchAll := len(stringIDs) == 0
	query := r.db.WithContext(ctx).Table("assets")

	// Add WHERE clause if we're not fetching all assets
	if !fetchAll {
		query = query.Where("id IN ?", stringIDs)
		logger.DebugContext(ctx, "Repository: Filtering export by %d specific asset IDs", len(stringIDs))
	} else {
		logger.DebugContext(ctx, "Repository: Exporting all assets")
	}

	// Select columns based on export type
	if exportType == domain.FullExport {
		logger.DebugContext(ctx, "Repository: Performing full export - all columns")
		var assets []map[string]interface{}
		if err := query.Find(&assets).Error; err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to fetch assets for full export: %v", err)
			return nil, err
		}
		exportData.Assets = assets
		logger.DebugContext(ctx, "Repository: Exported %d assets", len(assets))

		portsQuery := r.db.WithContext(ctx).Table("ports").
			Select("ports.*").
			Joins("LEFT JOIN assets ON ports.asset_id = assets.id AND assets.deleted_at IS NULL").
			Where("ports.deleted_at IS NULL")

		if !fetchAll {
			portsQuery = portsQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := portsQuery.Find(&exportData.Ports).Error; err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to fetch ports for export: %v", err)
			return nil, err
		}
		logger.DebugContext(ctx, "Repository: Exported %d ports", len(exportData.Ports))

		vmwareQuery := r.db.WithContext(ctx).Table("vmware_vms").
			Select("vmware_vms.*").
			Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id AND assets.deleted_at IS NULL")

		if !fetchAll {
			vmwareQuery = vmwareQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := vmwareQuery.Find(&exportData.VMwareVMs).Error; err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to fetch VMware VMs for export: %v", err)
			return nil, err
		}
		logger.DebugContext(ctx, "Repository: Exported %d VMware VMs", len(exportData.VMwareVMs))

		ipsQuery := r.db.WithContext(ctx).Table("asset_ips").
			Select("asset_ips.*").
			Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id AND assets.deleted_at IS NULL").
			Where("asset_ips.deleted_at IS NULL")

		if !fetchAll {
			ipsQuery = ipsQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := ipsQuery.Find(&exportData.AssetIPs).Error; err != nil {
			logger.ErrorContext(ctx, "Repository: Failed to fetch asset IPs for export: %v", err)
			return nil, err
		}
		logger.DebugContext(ctx, "Repository: Exported %d asset IPs", len(exportData.AssetIPs))
	} else {
		logger.DebugContext(ctx, "Repository: Performing selective export with custom columns")
		assetColumns := filterColumnsByTable(selectedColumns, "assets")
		portColumns := filterColumnsByTable(selectedColumns, "ports")
		vmwareColumns := filterColumnsByTable(selectedColumns, "vmware_vms")
		ipColumns := filterColumnsByTable(selectedColumns, "asset_ips")

		logger.DebugContext(ctx, "Repository: Column filtering - assets: %d, ports: %d, vmware: %d, ips: %d",
			len(assetColumns), len(portColumns), len(vmwareColumns), len(ipColumns))

		// Always include the ID column for assets to ensure proper relationship
		hasIDColumn := false
		for _, col := range assetColumns {
			if col == "id" {
				hasIDColumn = true
				break
			}
		}

		if !hasIDColumn {
			assetColumns = append(assetColumns, "id")
			logger.DebugContext(ctx, "Repository: Added ID column to ensure proper relationships")
		}

		// Export assets with selected columns
		if len(assetColumns) > 0 {
			if err := query.Select(assetColumns).Find(&exportData.Assets).Error; err != nil {
				logger.ErrorContext(ctx, "Repository: Failed to fetch assets with selected columns: %v", err)
				return nil, err
			}
			logger.DebugContext(ctx, "Repository: Exported %d assets with %d selected columns", len(exportData.Assets), len(assetColumns))
		}

		if len(portColumns) > 0 {
			prefixedPortColumns := make([]string, 0, len(portColumns)+1)
			for _, col := range portColumns {
				prefixedPortColumns = append(prefixedPortColumns, "ports."+col)
			}
			prefixedPortColumns = append(prefixedPortColumns, "ports.asset_id")

			portsQuery := r.db.WithContext(ctx).Table("ports").
				Select(strings.Join(prefixedPortColumns, ", ")).
				Joins("LEFT JOIN assets ON ports.asset_id = assets.id AND assets.deleted_at IS NULL").
				Where("ports.deleted_at IS NULL")

			if !fetchAll {
				portsQuery = portsQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := portsQuery.Find(&exportData.Ports).Error; err != nil {
				logger.ErrorContext(ctx, "Repository: Failed to fetch ports with selected columns: %v", err)
				return nil, err
			}
			logger.DebugContext(ctx, "Repository: Exported %d ports with %d selected columns", len(exportData.Ports), len(portColumns))
		}

		if len(vmwareColumns) > 0 {
			prefixedVMColumns := make([]string, 0, len(vmwareColumns)+1)
			for _, col := range vmwareColumns {
				prefixedVMColumns = append(prefixedVMColumns, "vmware_vms."+col)
			}
			prefixedVMColumns = append(prefixedVMColumns, "vmware_vms.asset_id")

			vmwareQuery := r.db.WithContext(ctx).Table("vmware_vms").
				Select(strings.Join(prefixedVMColumns, ", ")).
				Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id AND assets.deleted_at IS NULL")

			if !fetchAll {
				vmwareQuery = vmwareQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := vmwareQuery.Find(&exportData.VMwareVMs).Error; err != nil {
				logger.ErrorContext(ctx, "Repository: Failed to fetch VMware VMs with selected columns: %v", err)
				return nil, err
			}
			logger.DebugContext(ctx, "Repository: Exported %d VMware VMs with %d selected columns", len(exportData.VMwareVMs), len(vmwareColumns))
		}

		if len(ipColumns) > 0 {
			prefixedIPColumns := make([]string, 0, len(ipColumns)+1)
			for _, col := range ipColumns {
				prefixedIPColumns = append(prefixedIPColumns, "asset_ips."+col)
			}
			prefixedIPColumns = append(prefixedIPColumns, "asset_ips.asset_id")

			ipsQuery := r.db.WithContext(ctx).Table("asset_ips").
				Select(strings.Join(prefixedIPColumns, ", ")).
				Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id AND assets.deleted_at IS NULL").
				Where("asset_ips.deleted_at IS NULL")

			if !fetchAll {
				ipsQuery = ipsQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := ipsQuery.Find(&exportData.AssetIPs).Error; err != nil {
				logger.ErrorContext(ctx, "Repository: Failed to fetch asset IPs with selected columns: %v", err)
				return nil, err
			}
			logger.DebugContext(ctx, "Repository: Exported %d asset IPs with %d selected columns", len(exportData.AssetIPs), len(ipColumns))
		}
	}

	logger.InfoContextWithFields(ctx, "Repository: Successfully completed asset export", map[string]interface{}{
		"assets_exported": len(exportData.Assets),
		"ports_exported":  len(exportData.Ports),
		"vms_exported":    len(exportData.VMwareVMs),
		"ips_exported":    len(exportData.AssetIPs),
	})

	return exportData, nil
}

// filterColumnsByTable filters the selected columns by table prefix
func filterColumnsByTable(columns []string, tablePrefix string) []string {
	logger.Debug("Repository: Filtering columns by table prefix: %s", tablePrefix)

	prefix := tablePrefix + "."
	var result []string
	for _, col := range columns {
		if len(col) > len(prefix) && col[:len(prefix)] == prefix {
			result = append(result, col[len(prefix):])
		}
	}

	logger.Debug("Repository: Filtered %d columns for table %s", len(result), tablePrefix)
	logger.Debug("Repository: Filtered %d columns for table %s", len(result), tablePrefix)
	return result
}

// Helper function to apply filters to the query
func applyAssetFilters(baseDB *gorm.DB, query *gorm.DB, assetFilter domain.AssetFilters) *gorm.DB {
	logger.Debug("Repository: Applying asset filters to query")

	if utils.HasFilterValues(assetFilter.Name) {
		names := utils.SplitAndTrim(assetFilter.Name)
		if len(names) > 0 {
			logger.Debug("Repository: Applying name filter with %d values", len(names))
			subQuery := query.Where("assets.name LIKE ?", "%"+names[0]+"%")
			for i := 1; i < len(names); i++ {
				subQuery = subQuery.Or("assets.name LIKE ?", "%"+names[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	// Add the rest of the filter conditions
	if utils.HasFilterValues(assetFilter.Domain) {
		domains := utils.SplitAndTrim(assetFilter.Domain)
		if len(domains) > 0 {
			logger.Debug("Repository: Applying domain filter with %d values", len(domains))
			subQuery := query.Where("assets.domain LIKE ?", "%"+domains[0]+"%")
			for i := 1; i < len(domains); i++ {
				subQuery = subQuery.Or("assets.domain LIKE ?", "%"+domains[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Hostname) {
		hostnames := utils.SplitAndTrim(assetFilter.Hostname)
		if len(hostnames) > 0 {
			logger.Debug("Repository: Applying hostname filter with %d values", len(hostnames))
			subQuery := query.Where("assets.hostname LIKE ?", "%"+hostnames[0]+"%")
			for i := 1; i < len(hostnames); i++ {
				subQuery = subQuery.Or("assets.hostname LIKE ?", "%"+hostnames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSName) {
		osNames := utils.SplitAndTrim(assetFilter.OSName)
		if len(osNames) > 0 {
			logger.Debug("Repository: Applying OS name filter with %d values", len(osNames))
			subQuery := query.Where("assets.os_name LIKE ?", "%"+osNames[0]+"%")
			for i := 1; i < len(osNames); i++ {
				subQuery = subQuery.Or("assets.os_name LIKE ?", "%"+osNames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSVersion) {
		osVersions := utils.SplitAndTrim(assetFilter.OSVersion)
		if len(osVersions) > 0 {
			logger.Debug("Repository: Applying OS version filter with %d values", len(osVersions))
			subQuery := query.Where("assets.os_version LIKE ?", "%"+osVersions[0]+"%")
			for i := 1; i < len(osVersions); i++ {
				subQuery = subQuery.Or("assets.os_version LIKE ?", "%"+osVersions[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Type) {
		types := utils.SplitAndTrim(assetFilter.Type)
		if len(types) > 0 {
			logger.Debug("Repository: Applying asset type filter with %d values", len(types))
			subQuery := query.Where("assets.asset_type = ?", types[0])
			for i := 1; i < len(types); i++ {
				subQuery = subQuery.Or("assets.asset_type = ?", types[i])
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.IP) {
		logger.Debug("Repository: Applying IP filter with join")
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+assetFilter.IP+"%").
			Group("assets.id")
	}

	// Handle scanner type filter
	if utils.HasFilterValues(assetFilter.ScannerType) {
		scannerTypes := utils.SplitAndTrim(assetFilter.ScannerType)
		if len(scannerTypes) > 0 {
			logger.Debug("Repository: Applying scanner type filter with %d values", len(scannerTypes))
			// Join with asset_scan_jobs and scan_jobs tables to filter by scanner type
			subQuery := baseDB.Table("asset_scan_jobs asj").
				Select("asj.asset_id").
				Joins("JOIN scan_jobs ON asj.scan_job_id = scan_jobs.id").
				Joins("JOIN scanners ON scan_jobs.scanner_id = scanners.id").
				Where("scanners.scan_type IN ?", scannerTypes).
				Group("asj.asset_id")

			query = query.Where("assets.id IN (?)", subQuery)
		}
	}

	// Handle network filter
	if utils.HasFilterValues(assetFilter.Network) {
		networks := utils.SplitAndTrim(assetFilter.Network)
		if len(networks) > 0 {
			logger.Debug("Repository: Applying network filter with %d networks", len(networks))
			var assetIPsList utils.AssetIPsList

			if err := baseDB.WithContext(context.Background()).
				Table("asset_ips").
				Select("asset_id, ip_address").
				Where("deleted_at IS NULL").
				Find(&assetIPsList).Error; err != nil {

				logger.Error("Repository: Error fetching asset IPs for network filter: %v", err)
				return query
			}

			matchingAssetIDs, _ := utils.IpsInNetwork(networks, assetIPsList)

			ids := make([]string, 0, len(matchingAssetIDs))
			if len(matchingAssetIDs) > 0 {
				for id := range matchingAssetIDs {
					ids = append(ids, id)
				}
			}
			query = query.Where("assets.id IN (?)", ids)
			logger.Debug("Repository: Network filter matched %d asset IDs", len(ids))
		}
	}

	logger.Debug("Repository: Completed applying asset filters")
	return query
}

// ColumnMapping represents a database column mapping with metadata
type ColumnMapping struct {
	Column       string
	Table        string
	RequiresJoin bool
	JoinType     string
	JoinQuery    string
}

// TableJoinConfig holds join configuration for a table
type TableJoinConfig struct {
	Table     string
	JoinQuery string
	JoinType  string
}

var (
	// Join configurations for different tables
	joinConfigs = map[string]TableJoinConfig{
		"asset_ips": {
			Table:     "asset_ips",
			JoinQuery: "LEFT JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL",
			JoinType:  "LEFT",
		},
		"vmware_vms": {
			Table:     "vmware_vms",
			JoinQuery: "LEFT JOIN vmware_vms ON assets.id = vmware_vms.asset_id",
			JoinType:  "LEFT",
		},
		"scanners": {
			Table: "scanners",
			JoinQuery: `LEFT JOIN asset_scan_jobs asj ON assets.id = asj.asset_id
						LEFT JOIN scan_jobs sj ON asj.scan_job_id = sj.id  
						LEFT JOIN scanners ON sj.scanner_id = scanners.id`,
			JoinType: "LEFT",
		},
	}

	// Scanner field mappings - these need special mapping
	scannerFieldMappings = map[string]string{
		"scanner.type": "scanners.scan_type",
	}

	// Assets table fields - just field names, columns are auto-generated
	assetFields = []string{
		"name", "domain", "hostname", "os_name", "os_version", "asset_type",
		"description", "created_at", "updated_at", "logging_completed",
		"asset_value", "risk",
	}
)

// Helper function to map request field names to database column names with join information
func mapFieldToDBColumn(field string) ColumnMapping {
	logger.Debug("Repository: Mapping field to DB column: %s", field)

	// Handle special field mappings first
	switch field {
	case "ip_address":
		logger.Debug("Repository: Mapped field %s to IP address column with join", field)
		return ColumnMapping{
			Column:       "asset_ips.ip_address",
			Table:        "asset_ips",
			RequiresJoin: true,
			JoinType:     joinConfigs["asset_ips"].JoinType,
			JoinQuery:    joinConfigs["asset_ips"].JoinQuery,
		}
	}

	// Handle scanner fields with special mapping
	if column, exists := scannerFieldMappings[field]; exists {
		logger.Debug("Repository: Mapped scanner field %s to column %s", field, column)
		return ColumnMapping{
			Column:       column,
			Table:        "scanners",
			RequiresJoin: true,
			JoinType:     joinConfigs["scanners"].JoinType,
			JoinQuery:    joinConfigs["scanners"].JoinQuery,
		}
	}

	// Check if it's a table-prefixed field (like "asset_ips.ip_address" or "vmware_vms.vm_name")
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		if len(parts) == 2 {
			tableName := parts[0]
			columnName := parts[1]

			// For prefixed fields, the key equals the column (pattern you noticed)
			fullColumn := tableName + "." + columnName

			if joinConfig, exists := joinConfigs[tableName]; exists {
				logger.Debug("Repository: Mapped prefixed field %s to column %s with join", field, fullColumn)
				return ColumnMapping{
					Column:       fullColumn,
					Table:        tableName,
					RequiresJoin: true,
					JoinType:     joinConfig.JoinType,
					JoinQuery:    joinConfig.JoinQuery,
				}
			}
		}
	}

	// Check if it's an assets table field
	for _, assetField := range assetFields {
		if field == assetField {
			columnName := field
			logger.Debug("Repository: Mapped assets field %s to column %s", field, "assets."+columnName)
			return ColumnMapping{
				Column: "assets." + columnName,
				Table:  "assets",
			}
		}
	}

	// Default fallback
	logger.Debug("Repository: Using default fallback mapping for field: %s", field)
	return ColumnMapping{Column: "assets.created_at", Table: "assets"}
}

// GetDistinctOSNames returns a list of distinct OS names from all assets
func (r *assetRepository) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	logger.InfoContext(ctx, "Repository: Getting distinct OS names")

	var osNames []string

	err := r.db.WithContext(ctx).
		Model(&types.Asset{}).
		Select("DISTINCT os_name").
		Where("os_name IS NOT NULL AND os_name != ''").
		Order("os_name ASC").
		Pluck("os_name", &osNames).Error

	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to get distinct OS names: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "Repository: Retrieved %d distinct OS names", len(osNames))
	return osNames, nil
}

// createAssetWithTx creates an asset record in a transaction
func (r *assetRepository) createAssetWithTx(tx *gorm.DB, assetRecord *types.Asset) error {
	logger.Debug("Repository: Creating asset record with transaction - ID: %s", assetRecord.ID)

	if err := tx.Table("assets").Create(assetRecord).Error; err != nil {
		logger.Error("Repository: Error creating asset: %v", err)
		return err
	}

	logger.Debug("Repository: Successfully created asset record - ID: %s", assetRecord.ID)
	return nil
}

// createPortsWithTx creates port records for an asset in a transaction
func (r *assetRepository) createPortsWithTx(tx *gorm.DB, ports []types.Port, assetID string) error {
	logger.Debug("Repository: Creating %d ports for asset %s in transaction", len(ports), assetID)

	for i, port := range ports {
		port.AssetID = assetID
		if err := tx.Table("ports").Create(&port).Error; err != nil {
			logger.Error("Repository: Error creating port %d/%s for asset %s: %v",
				port.PortNumber, port.Protocol, assetID, err)
			return err
		}
		logger.Debug("Repository: Created port %d/%s (%d/%d) for asset %s",
			port.PortNumber, port.Protocol, i+1, len(ports), assetID)
	}

	if len(ports) > 0 {
		logger.Info("Repository: Created %d ports for asset %s", len(ports), assetID)
	} else {
		logger.Debug("Repository: No ports to create for asset %s", assetID)
	}
	return nil
}

// updateOrUndeleteIP updates an existing IP record, optionally undeleting it
func (r *assetRepository) updateOrUndeleteIP(tx *gorm.DB, foundIP types.AssetIP, newAssetID string, macAddress string) error {
	logger.Debug("Repository: Updating/undeleting IP %s for asset %s", foundIP.IPAddress, newAssetID)

	now := time.Now()
	updates := map[string]interface{}{
		"asset_id":   newAssetID,
		"updated_at": now,
	}

	// If the IP is deleted, undelete it
	if foundIP.DeletedAt != nil {
		updates["deleted_at"] = nil
		logger.Info("Repository: Undeleting IP %s and assigning to new asset %s", foundIP.IPAddress, newAssetID)
	} else {
		logger.Info("Repository: Reassigning existing IP %s to new asset %s", foundIP.IPAddress, newAssetID)
	}

	// Update MAC address if provided
	if macAddress != "" {
		updates["mac_address"] = macAddress
		logger.Debug("Repository: Updating MAC address for IP %s to %s", foundIP.IPAddress, macAddress)
	}

	// Update the IP record
	if err := tx.Table("asset_ips").Where("id = ?", foundIP.ID).Updates(updates).Error; err != nil {
		logger.Error("Repository: Error updating IP %s: %v", foundIP.IPAddress, err)
		return err
	}

	logger.Debug("Repository: Successfully updated IP %s for asset %s", foundIP.IPAddress, newAssetID)
	return nil
}

// createNewIPs creates new IP records in a transaction
func (r *assetRepository) createNewIPs(tx *gorm.DB, assetIPs []*types.AssetIP, processedIPs map[string]bool) error {
	logger.Debug("Repository: Creating new IPs - total: %d, processed: %d", len(assetIPs), len(processedIPs))

	createdCount := 0
	for _, assetIPPtr := range assetIPs {
		if assetIPPtr == nil {
			logger.Debug("Repository: Skipping nil IP pointer")
			continue
		}

		if !processedIPs[assetIPPtr.IPAddress] {
			if err := tx.Table("asset_ips").Create(assetIPPtr).Error; err != nil {
				logger.Error("Repository: Error creating new IP %s: %v", assetIPPtr.IPAddress, err)
				return err
			}
			logger.Info("Repository: Created new IP %s for asset %s", assetIPPtr.IPAddress, assetIPPtr.AssetID)
			createdCount++
		} else {
			logger.Debug("Repository: Skipping already processed IP: %s", assetIPPtr.IPAddress)
		}
	}

	logger.Debug("Repository: Successfully created %d new IPs", createdCount)
	return nil
}

// findExistingIPs finds existing IPs for a list of IP addresses and categorizes them
func (r *assetRepository) findExistingIPs(ctx context.Context, ipAddresses []string) ([]types.AssetIP, []types.AssetIP, error) {
	logger.DebugContext(ctx, "Repository: Finding existing IPs for %d addresses", len(ipAddresses))

	var foundIPs []types.AssetIP
	if err := r.db.WithContext(ctx).Table("asset_ips").Where("ip_address IN ?", ipAddresses).Find(&foundIPs).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Error checking for existing IPs: %v", err)
		return nil, nil, err
	}

	logger.DebugContext(ctx, "Repository: Found %d existing IP records", len(foundIPs))

	// Separate into deleted and non-deleted IPs
	var existingActiveIPs []types.AssetIP
	var existingDeletedIPs []types.AssetIP

	for _, ip := range foundIPs {
		if ip.DeletedAt == nil {
			existingActiveIPs = append(existingActiveIPs, ip)
		} else {
			existingDeletedIPs = append(existingDeletedIPs, ip)
		}
	}

	logger.DebugContext(ctx, "Repository: Categorized IPs - active: %d, deleted: %d",
		len(existingActiveIPs), len(existingDeletedIPs))

	return existingActiveIPs, existingDeletedIPs, nil
}

// checkActiveIPsAssets checks if active IPs belong to non-deleted assets
func (r *assetRepository) checkActiveIPsAssets(ctx context.Context, activeIPs []types.AssetIP) (bool, error) {
	if len(activeIPs) == 0 {
		logger.DebugContext(ctx, "Repository: No active IPs to check")
		return false, nil
	}

	logger.DebugContext(ctx, "Repository: Checking %d active IPs for asset conflicts", len(activeIPs))

	// Get the first active IP to check its asset
	activeIP := activeIPs[0]

	var existingAsset types.Asset
	if err := r.db.WithContext(ctx).Table("assets").Where("id = ?", activeIP.AssetID).First(&existingAsset).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Error finding existing asset for IP %s: %v", activeIP.IPAddress, err)
		return false, err
	}

	// If the asset is not deleted, return true indicating IP conflict
	if existingAsset.DeletedAt == nil {
		logger.WarnContext(ctx, "Repository: Asset with IP %s already exists and is not deleted (Asset ID: %s)",
			activeIP.IPAddress, existingAsset.ID)
		return true, nil
	}

	// Asset is deleted but IP is not
	logger.InfoContext(ctx, "Repository: Found active IP(s) belonging to deleted asset(s), will create new asset and reassign IPs")
	return false, nil
}

// findMACForIP finds MAC address for a given IP in the list of valid asset IPs
func (r *assetRepository) findMACForIP(ip string, validAssetIPs []domain.AssetIP) string {
	logger.Debug("Repository: Finding MAC address for IP: %s", ip)

	for _, assetIP := range validAssetIPs {
		if assetIP.IP == ip && assetIP.MACAddress != "" {
			logger.Debug("Repository: Found MAC address %s for IP %s", assetIP.MACAddress, ip)
			return assetIP.MACAddress
		}
	}

	logger.Debug("Repository: No MAC address found for IP: %s", ip)
	return ""
}

// beginTransaction begins a database transaction
func (r *assetRepository) beginTransaction(ctx context.Context) (*gorm.DB, error) {
	logger.DebugContext(ctx, "Repository: Beginning database transaction")

	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Repository: Failed to begin transaction: %v", tx.Error)
		return nil, tx.Error
	}

	logger.DebugContext(ctx, "Repository: Successfully began database transaction")
	return tx, nil
}

// handleExistingIPs checks and processes existing IPs when creating a new asset
func (r *assetRepository) handleExistingIPs(ctx context.Context, tx *gorm.DB, asset domain.AssetDomain,
	validAssetIPs []domain.AssetIP, assetRecord *types.Asset, assetIPs []*types.AssetIP, portRecords []types.Port) error {

	logger.DebugContext(ctx, "Repository: Handling existing IPs for asset %s with %d valid IPs",
		asset.ID.String(), len(validAssetIPs))

	// Collect all IP addresses to check
	var ipAddresses []string
	for _, ip := range validAssetIPs {
		ipAddresses = append(ipAddresses, ip.IP)
	}

	logger.DebugContext(ctx, "Repository: Checking %d IP addresses for conflicts", len(ipAddresses))

	// Find any existing IPs in the database
	existingActiveIPs, existingDeletedIPs, err := r.findExistingIPs(ctx, ipAddresses)
	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to find existing IPs: %v", err)
		return err
	}

	// If any non-deleted IPs exist, check if they belong to a non-deleted asset
	if len(existingActiveIPs) > 0 {
		logger.DebugContext(ctx, "Repository: Found %d existing active IPs, checking for conflicts", len(existingActiveIPs))
		isConflict, err := r.checkActiveIPsAssets(ctx, existingActiveIPs)
		if err != nil {
			return err
		}
		if isConflict {
			logger.WarnContext(ctx, "Repository: IP conflict detected, cannot create asset")
			return domain.ErrIPAlreadyExists
		}
	}

	// Create the asset record
	logger.DebugContext(ctx, "Repository: Creating asset record")
	if err := r.createAssetWithTx(tx, assetRecord); err != nil {
		return err
	}

	// Create ports for the asset
	logger.DebugContext(ctx, "Repository: Creating %d ports for asset", len(portRecords))
	if err := r.createPortsWithTx(tx, portRecords, asset.ID.String()); err != nil {
		return err
	}

	// Track the IPs we've processed to avoid duplicates
	processedIPs := make(map[string]bool)

	// First, handle all active IPs (belonging to deleted assets)
	logger.DebugContext(ctx, "Repository: Processing %d active IPs from deleted assets", len(existingActiveIPs))
	for _, foundIP := range existingActiveIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Update the IP record with asset ID and possibly MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Then handle deleted IPs that need to be undeleted
	logger.DebugContext(ctx, "Repository: Processing %d deleted IPs to undelete", len(existingDeletedIPs))
	for _, foundIP := range existingDeletedIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Undelete the IP record and update with asset ID and MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Finally, create any new IPs that weren't found in the database
	logger.DebugContext(ctx, "Repository: Creating new IPs not found in database")
	if err := r.createNewIPs(tx, assetIPs, processedIPs); err != nil {
		return err
	}

	logger.InfoContext(ctx, "Repository: Successfully processed existing IPs and created new ones for asset %s", asset.ID)
	return nil
}

func (r *assetRepository) getScannerTypes(ctx context.Context, assetIDs []string) map[string]string {
	logger.DebugContext(ctx, "Repository: Getting scanner types for %d assets", len(assetIDs))

	scannerTypeMap := make(map[string]string)

	if len(assetIDs) > 0 {
		type ScannerTypeResult struct {
			AssetID  string `gorm:"column:asset_id"`
			ScanType string `gorm:"column:scan_type"`
		}

		var results []ScannerTypeResult

		latestScanJobSubquery := r.db.WithContext(ctx).
			Table("asset_scan_jobs asj1").
			Select("asj1.asset_id, MAX(asj1.discovered_at) as latest_discovery").
			Where("asj1.asset_id IN ?", assetIDs).
			Group("asj1.asset_id")

		query := r.db.WithContext(ctx).
			Table("asset_scan_jobs asj").
			Select("asj.asset_id, scanners.scan_type").
			Joins("JOIN scan_jobs ON asj.scan_job_id = scan_jobs.id").
			Joins("JOIN scanners ON scan_jobs.scanner_id = scanners.id").
			Joins("JOIN (?) as latest ON asj.asset_id = latest.asset_id AND asj.discovered_at = latest.latest_discovery", latestScanJobSubquery)

		if err := query.Find(&results).Error; err != nil {
			logger.ErrorContext(ctx, "Repository: Error getting scanner types for assets: %v", err)
		} else {
			for _, result := range results {
				scannerTypeMap[result.AssetID] = result.ScanType
			}
			logger.DebugContext(ctx, "Repository: Retrieved scanner types for %d assets", len(results))
		}
	} else {
		logger.DebugContext(ctx, "Repository: No asset IDs provided for scanner type lookup")
	}

	return scannerTypeMap
}

func (r *assetRepository) updateDiscoveredBy(currentDiscoveredBy, scannerType string) string {
	if currentDiscoveredBy == "" {
		return scannerType
	}

	// Check if scanner type already exists in the discovered_by field
	scanners := strings.Split(currentDiscoveredBy, ", ")
	for _, scanner := range scanners {
		if strings.TrimSpace(scanner) == scannerType {
			return currentDiscoveredBy // Already exists, no change needed
		}
	}

	// Add new scanner type
	return currentDiscoveredBy + ", " + scannerType
}

// CreateWithScannerType creates an asset with scanner type information
func (r *assetRepository) CreateWithScannerType(ctx context.Context, asset domain.AssetDomain, scannerType string) (domain.AssetUUID, error) {
	logger.InfoContextWithFields(ctx, "Repository: Creating asset with scanner type", map[string]interface{}{
		"asset_id":     asset.ID.String(),
		"asset_name":   asset.Name,
		"hostname":     asset.Hostname,
		"scanner_type": scannerType,
	})

	// Set the discovered_by field
	asset.DiscoveredBy = scannerType

	// Call the existing Create method
	return r.Create(ctx, asset)
}

func (r *assetRepository) handleExistingIPsWithScanner(ctx context.Context, tx *gorm.DB, asset domain.AssetDomain,
	validAssetIPs []domain.AssetIP, assetRecord *types.Asset, assetIPs []*types.AssetIP, portRecords []types.Port) error {

	logger.DebugContext(ctx, "Repository: Handling existing IPs for asset %s with %d valid IPs",
		asset.ID.String(), len(validAssetIPs))

	// Collect all IP addresses to check
	var ipAddresses []string
	for _, ip := range validAssetIPs {
		ipAddresses = append(ipAddresses, ip.IP)
	}

	logger.DebugContext(ctx, "Repository: Checking %d IP addresses for conflicts", len(ipAddresses))

	// Find any existing IPs in the database
	existingActiveIPs, existingDeletedIPs, err := r.findExistingIPs(ctx, ipAddresses)
	if err != nil {
		logger.ErrorContext(ctx, "Repository: Failed to find existing IPs: %v", err)
		return err
	}

	// If any non-deleted IPs exist, check if they belong to a non-deleted asset
	if len(existingActiveIPs) > 0 {
		logger.DebugContext(ctx, "Repository: Found %d existing active IPs, checking for conflicts", len(existingActiveIPs))
		isConflict, existingAssetID, err := r.checkActiveIPsAssetsWithUpdate(ctx, existingActiveIPs, asset.DiscoveredBy)
		if err != nil {
			return err
		}
		if isConflict {
			logger.WarnContext(ctx, "Repository: IP conflict detected, cannot create asset")
			return domain.ErrIPAlreadyExists
		}

		// If we found an existing asset that we can update, return its ID
		if existingAssetID != "" {
			// Update the existing asset's discovered_by field
			var existingAsset types.Asset
			if err := tx.Table("assets").Where("id = ?", existingAssetID).First(&existingAsset).Error; err == nil {
				currentDiscoveredBy := ""
				if existingAsset.DiscoveredBy != nil {
					currentDiscoveredBy = *existingAsset.DiscoveredBy
				}

				updatedDiscoveredBy := r.updateDiscoveredBy(currentDiscoveredBy, asset.DiscoveredBy)
				if err := tx.Table("assets").Where("id = ?", existingAssetID).
					Update("discovered_by", updatedDiscoveredBy).Error; err != nil {
					return err
				}

				logger.InfoContext(ctx, "Repository: Updated existing asset %s discovered_by to: %s",
					existingAssetID, updatedDiscoveredBy)
			}
			return nil
		}
	}

	// Continue with the rest of the method as before...
	// Create the asset record
	logger.DebugContext(ctx, "Repository: Creating asset record")
	if err := r.createAssetWithTx(tx, assetRecord); err != nil {
		return err
	}

	// Create ports for the asset
	logger.DebugContext(ctx, "Repository: Creating %d ports for asset", len(portRecords))
	if err := r.createPortsWithTx(tx, portRecords, asset.ID.String()); err != nil {
		return err
	}

	// Track the IPs we've processed to avoid duplicates
	processedIPs := make(map[string]bool)

	// First, handle all active IPs (belonging to deleted assets)
	logger.DebugContext(ctx, "Repository: Processing %d active IPs from deleted assets", len(existingActiveIPs))
	for _, foundIP := range existingActiveIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Update the IP record with asset ID and possibly MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Then handle deleted IPs that need to be undeleted
	logger.DebugContext(ctx, "Repository: Processing %d deleted IPs to undelete", len(existingDeletedIPs))
	for _, foundIP := range existingDeletedIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Undelete the IP record and update with asset ID and MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Finally, create any new IPs that weren't found in the database
	logger.DebugContext(ctx, "Repository: Creating new IPs not found in database")
	if err := r.createNewIPs(tx, assetIPs, processedIPs); err != nil {
		return err
	}

	logger.InfoContext(ctx, "Repository: Successfully processed existing IPs and created new ones for asset %s", asset.ID)
	return nil
}

// Updated checkActiveIPsAssets method to handle discovered_by updates
func (r *assetRepository) checkActiveIPsAssetsWithUpdate(ctx context.Context, activeIPs []types.AssetIP, newScannerType string) (bool, string, error) {
	if len(activeIPs) == 0 {
		logger.DebugContext(ctx, "Repository: No active IPs to check")
		return false, "", nil
	}

	logger.DebugContext(ctx, "Repository: Checking %d active IPs for asset conflicts", len(activeIPs))

	// Get the first active IP to check its asset
	activeIP := activeIPs[0]

	var existingAsset types.Asset
	if err := r.db.WithContext(ctx).Table("assets").Where("id = ?", activeIP.AssetID).First(&existingAsset).Error; err != nil {
		logger.ErrorContext(ctx, "Repository: Error finding existing asset for IP %s: %v", activeIP.IPAddress, err)
		return false, "", err
	}

	// If the asset is not deleted, we can update its discovered_by field
	if existingAsset.DeletedAt == nil {
		logger.InfoContext(ctx, "Repository: Found existing active asset %s for IP %s, will update discovered_by field",
			existingAsset.ID, activeIP.IPAddress)
		return false, existingAsset.ID, nil
	}

	// Asset is deleted but IP is not
	logger.InfoContext(ctx, "Repository: Found active IP(s) belonging to deleted asset(s), will create new asset and reassign IPs")
	return false, "", nil
}
