package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Scanner interface{} `json:"scanner,omitempty"`
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
}

// SuccessResponse represents a standardized success response
type SuccessResponse struct {
	Scanner interface{} `json:"scanner"`
	Success bool        `json:"success"`
}

// OrderedScanner represents the scanner data in the desired JSON order
type OrderedScanner struct {
	ScanName  interface{} `json:"scan_name"`
	Type      interface{} `json:"type"`
	Target    string      `json:"target"`
	Status    bool        `json:"status"`
	ID        interface{} `json:"id,omitempty"`
	CreatedAt interface{} `json:"created_at,omitempty"`
	UpdatedAt interface{} `json:"updated_at,omitempty"`
	Domain    interface{} `json:"domain,omitempty"`
}

// ScannerWithTarget combines a scanner with its computed target field
type ScannerWithTarget struct {
	Scanner     *pb.Scanner
	Target      string
	OrderedData OrderedScanner
}

func CreateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.CreateScannerRequest
		if err := c.BodyParser(&req); err != nil {
			context.GetLogger(c.UserContext()).Error("Failed to parse request body", "error", err)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Failed to parse request body",
			})
		}

		// Validate firewall-specific fields if this is a firewall scanner
		if req.ScanType == "FIREWALL" {
			if err := validateFirewallScannerRequest(&req); err != nil {
				context.GetLogger(c.UserContext()).Error("Firewall scanner validation failed", "error", err)
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   err.Error(),
				})
			}
		}

		// Validate run_once schedule if schedule is provided
		if req.Schedule != nil {
			if err := validateRunOnceSchedule(req.Schedule.ScheduleType, req.Schedule.RunTime); err != nil {
				context.GetLogger(c.UserContext()).Error("Run once schedule validation failed", "error", err)
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   err.Error(),
				})
			}
		}

		// Call the service to create the scanner
		response, err := srv.CreateScanner(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   "Invalid scanner input",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.Status(fiber.StatusCreated).JSON(SuccessResponse{
			Scanner: response.Scanner,
			Success: true,
		})
	}
}

func UpdateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get scanner ID from URL parameter
		id := c.Params("id")
		if id == "" {
			logger.Error("Scanner ID is empty for update request")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		// Get the raw body
		body := c.Body()

		// Parse the raw request to access the schedule object
		var rawRequest map[string]interface{}
		if err := json.Unmarshal(body, &rawRequest); err != nil {
			logger.Error("Failed to parse raw request", "error", err)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Failed to parse request body",
			})
		}

		// Parse the request into the protobuf struct
		var req pb.UpdateScannerRequest
		if err := json.Unmarshal(body, &req); err != nil {
			logger.Error("Failed to parse request into UpdateScannerRequest", "error", err)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Failed to parse request into UpdateScannerRequest",
			})
		}

		// Set the ID from the path parameter
		req.Id = id

		// Validate firewall-specific fields if this is a firewall scanner
		if req.ScanType == "FIREWALL" {
			if err := validateFirewallScannerUpdateRequest(&req); err != nil {
				logger.Error("Firewall scanner update validation failed", "error", err)
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   err.Error(),
				})
			}
		}

		// Validate run_once schedule if schedule object exists and has run_once type
		if scheduleObj, ok := rawRequest["schedule"].(map[string]interface{}); ok {
			var scheduleType, runTime string
			if st, exists := scheduleObj["schedule_type"].(string); exists {
				scheduleType = st
			}
			if rt, exists := scheduleObj["run_time"].(string); exists {
				runTime = rt
			}

			if err := validateRunOnceSchedule(scheduleType, runTime); err != nil {
				logger.Error("Run once schedule validation failed", "error", err)
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   err.Error(),
				})
			}
		}

		// Process schedule fields if schedule object exists
		if scheduleObj, ok := rawRequest["schedule"].(map[string]interface{}); ok {
			logger.Info("Processing schedule object for scanner update")
			processScheduleFields(scheduleObj, &req)
			// Log the processed schedule data for debugging
			logger.Info("Processed schedule data",
				"schedule_type", req.ScheduleType,
				"frequency_value", req.FrequencyValue,
				"frequency_unit", req.FrequencyUnit,
				"run_time", req.RunTime,
				"hour", req.Hour,
				"minute", req.Minute,
				"day", req.Day,
				"week", req.Week,
				"month", req.Month)
		} else {
			logger.Info("No schedule object found in request")
		}

		logger.Info("Processing scanner update request", "id", id)

		// Call the service to update the scanner
		response, err := srv.UpdateScanner(ctx, &req)
		if err != nil {
			logger.Error("Failed to update scanner", "id", id, "error", err)
			if errors.Is(err, service.ErrScannerNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Scanner not found",
				})
			} else if errors.Is(err, service.ErrInvalidScannerInput) {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   "Invalid scanner input",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.Info("Scanner updated successfully", "id", id)
		return c.JSON(SuccessResponse{
			Scanner: response.Scanner,
			Success: true,
		})
	}
}

// validateRunOnceSchedule validates a run_once schedule with unified logic
func validateRunOnceSchedule(scheduleType, runTime string) error {
	// Check if this is a RUN_ONCE schedule
	if strings.ToUpper(scheduleType) != "RUN_ONCE" {
		return nil // Not a run_once schedule, no validation needed
	}

	// For RUN_ONCE schedules, run_time must be provided
	if runTime == "" {
		return fmt.Errorf("run_time is required for RUN_ONCE schedule type")
	}

	// Parse the run_time
	parsedRunTime, err := parseRunTimeString(runTime)
	if err != nil {
		return fmt.Errorf("invalid run_time format: %v", err)
	}

	// Check if run_time is in the future
	now := time.Now()
	if !parsedRunTime.After(now) {
		return fmt.Errorf("run_time must be in the future. Current time: %s, provided run_time: %s",
			now.Format("2006-01-02 15:04:05"), parsedRunTime.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// parseRunTimeString parses a run_time string using multiple formats
func parseRunTimeString(runTimeStr string) (time.Time, error) {
	// Try parsing with different formats in order of preference
	formats := []string{
		"2006-01-02 15:04:05",       // Local time format
		"2006-01-02T15:04:05Z07:00", // RFC3339 with timezone
		"2006-01-02T15:04:05Z",      // RFC3339 UTC
		"2006-01-02 15:04",          // Without seconds
		"2006-01-02T15:04:05",       // ISO format without timezone
	}

	// First try parsing as local time
	if runTime, err := time.ParseInLocation(formats[0], runTimeStr, time.Local); err == nil {
		return runTime, nil
	}

	// Try other formats
	for _, format := range formats[1:] {
		if runTime, err := time.Parse(format, runTimeStr); err == nil {
			return runTime, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time format: %s. Expected formats: %v", runTimeStr, formats)
}

// formatTargetField creates a consolidated target string based on scanner properties and scanner type
func formatTargetField(scanner *pb.Scanner) string {
	// Handle formatting based on scanner type
	switch scanner.ScanType {
	case "NMAP":
		// For NMAP scanners, use Target field to determine formatting
		if scanner.Target == "" {
			return ""
		}
		switch scanner.Target {
		case "IP":
			return scanner.Ip
		case "Network":
			if scanner.Ip != "" && scanner.Subnet > 0 {
				return fmt.Sprintf("%s/%d", scanner.Ip, scanner.Subnet)
			}
		case "Range":
			if scanner.StartIp != "" && scanner.EndIp != "" {
				return fmt.Sprintf("%s to %s", scanner.StartIp, scanner.EndIp)
			}
		}
		return ""
	case "VCENTER":
		// For VCenter scanners, format as IP:Port
		if scanner.Ip != "" {
			if scanner.Port != "" {
				return fmt.Sprintf("%s:%s", scanner.Ip, scanner.Port)
			}
			return scanner.Ip
		}
		return ""
	case "DOMAIN":
		// For Domain scanners, format as Domain (IP:Port)
		if scanner.Domain != "" && scanner.Ip != "" && scanner.Port != "" {
			return fmt.Sprintf("%s (%s:%s)", scanner.Domain, scanner.Ip, scanner.Port)
		} else if scanner.Domain != "" {
			return scanner.Domain
		} else if scanner.Ip != "" {
			if scanner.Port != "" {
				return fmt.Sprintf("%s:%s", scanner.Ip, scanner.Port)
			}
			return scanner.Ip
		}
		return ""
	case "FIREWALL":
		// For Firewall scanners, format as IP:Port with API key indicator
		if scanner.Ip != "" {
			target := scanner.Ip
			if scanner.Port != "" {
				target = fmt.Sprintf("%s:%s", scanner.Ip, scanner.Port)
			}
			return target
		}
		return ""
	default:
		return ""
	}
}

// validateFirewallScannerRequest validates firewall scanner creation request
func validateFirewallScannerRequest(req *pb.CreateScannerRequest) error {
	if req.Ip == "" {
		return fmt.Errorf("IP address is required for firewall scanner")
	}
	if req.Port == "" {
		return fmt.Errorf("port is required for firewall scanner")
	}

	// Validate IP format (basic validation)
	if !isValidIPFormat(req.Ip) {
		return fmt.Errorf("invalid IP address format: %s", req.Ip)
	}

	// Validate port (basic validation)
	if !isValidPortFormat(req.Port) {
		return fmt.Errorf("invalid port format: %s", req.Port)
	}

	return nil
}

// validateFirewallScannerUpdateRequest validates firewall scanner update request
func validateFirewallScannerUpdateRequest(req *pb.UpdateScannerRequest) error {
	// Only validate if fields are provided (not empty)
	if req.Ip != "" && !isValidIPFormat(req.Ip) {
		return fmt.Errorf("invalid IP address format: %s", req.Ip)
	}
	if req.Port != "" && !isValidPortFormat(req.Port) {
		return fmt.Errorf("invalid port format: %s", req.Port)
	}
	return nil
}

// isValidIPFormat performs basic IP address validation
func isValidIPFormat(ip string) bool {
	if ip == "" {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// isValidPortFormat performs basic port validation
func isValidPortFormat(port string) bool {
	if port == "" {
		return false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return portNum > 0 && portNum <= 65535
}

// Enhanced ListScanners handler with firewall scanner support
func ListScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())

		// Extract pagination parameters
		limit := c.QueryInt("limit", 0)
		page := c.QueryInt("page", 0)
		originalSortField, sortOrder := extractSortParameters(c)

		// Check if we're sorting by target
		isTargetSort := (originalSortField == "target")

		// Get filters
		scannerName := c.Query("name", "")
		if scannerName == "" {
			scannerName = c.Query("filter[name]", "")
		}

		scanType := c.Query("type", "")
		if scanType == "" {
			scanType = c.Query("filter[scan_type]", "")
			if scanType == "" {
				scanType = c.Query("filter[type]", "")
			}
		}

		// Handle boolean status filter
		statusParam := c.Query("status", c.Query("filter[status]", ""))
		var statusValue bool
		var hasStatusFilter bool

		req := &pb.ListScannersRequest{
			Name:     scannerName,
			ScanType: scanType,
		}

		if statusParam != "" {
			hasStatusFilter = true
			req.HasStatusFilter = true
			if statusParam == "true" || statusParam == "1" {
				statusValue = true
				req.Status = true
			} else if statusParam == "false" || statusParam == "0" {
				statusValue = false
				req.Status = false
			}
			logger.Info("Setting status filter from URL", "status", statusValue)
		}

		logger.Info("Parsing filter parameters from URL query",
			"limit", limit,
			"page", page,
			"original_sort_field", originalSortField,
			"sort_order", sortOrder,
			"is_target_sort", isTargetSort,
			"name", scannerName,
			"scan_type", scanType,
			"status", statusParam,
			"has_status_filter", hasStatusFilter)

		var response *pb.ListScannersResponse
		var totalCount int
		var err error

		if isTargetSort {
			// When sorting by target, we need to get all records first, then sort and paginate manually
			logger.Info("Sorting by target field - retrieving all records for proper sorting")
			response, totalCount, err = srv.ListScanners(
				c.UserContext(),
				req,
				0,    // No limit - get all records
				0,    // No page offset
				"id", // Default sort by ID
				"asc",
			)
		} else {
			// Normal database-level sorting - now map the API field to DB column
			dbSortField := mapAPIFieldToDBColumn(originalSortField)
			logger.Info("Using database-level sorting", "api_field", originalSortField, "db_field", dbSortField)
			response, totalCount, err = srv.ListScanners(
				c.UserContext(),
				req,
				limit,
				page,
				dbSortField,
				sortOrder,
			)
		}

		if err != nil {
			logger.Error("Failed to list scanners", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		// Process scanner data and compute target fields
		scannersWithTarget := make([]ScannerWithTarget, 0, len(response.Scanners))

		for _, scanner := range response.Scanners {
			// Convert scanner to map to access all fields
			scannerBytes, _ := json.Marshal(scanner)
			var scannerMap map[string]interface{}
			json.Unmarshal(scannerBytes, &scannerMap)

			// Compute the target field
			targetValue := formatTargetField(scanner)

			// Create ordered struct
			ordered := OrderedScanner{
				ScanName: scannerMap["name"],
				Type:     scannerMap["scan_type"],
				Target:   targetValue,
				Status:   scanner.Status,
				ID:       scannerMap["id"],
			}

			// Add optional fields if they exist
			if val, ok := scannerMap["created_at"]; ok {
				ordered.CreatedAt = val
			}
			if val, ok := scannerMap["updated_at"]; ok {
				ordered.UpdatedAt = val
			}
			if val, ok := scannerMap["domain"]; ok {
				ordered.Domain = val
			}

			scannersWithTarget = append(scannersWithTarget, ScannerWithTarget{
				Scanner:     scanner,
				Target:      targetValue,
				OrderedData: ordered,
			})
		}

		// Sort by target if requested
		if isTargetSort {
			logger.Info("Applying target-based sorting", "order", sortOrder, "count", len(scannersWithTarget))
			sort.Slice(scannersWithTarget, func(i, j int) bool {
				target1 := scannersWithTarget[i].Target
				target2 := scannersWithTarget[j].Target

				if sortOrder == "desc" {
					return target1 > target2
				}
				return target1 < target2
			})

			// Apply manual pagination for target sorting
			startIndex := page * limit
			endIndex := startIndex + limit

			if startIndex > len(scannersWithTarget) {
				startIndex = len(scannersWithTarget)
			}
			if endIndex > len(scannersWithTarget) {
				endIndex = len(scannersWithTarget)
			}

			// Only take the requested page when sorting by target
			if limit > 0 {
				scannersWithTarget = scannersWithTarget[startIndex:endIndex]
				logger.Info("Applied pagination for target sort", "start", startIndex, "end", endIndex, "final_count", len(scannersWithTarget))
			}
		}

		// Build final contents array
		contents := make([]interface{}, 0, len(scannersWithTarget))
		for _, scannerWithTarget := range scannersWithTarget {
			contents = append(contents, scannerWithTarget.OrderedData)
		}

		// Add status to filter response if it was part of the request
		filterObj := map[string]interface{}{
			"name":      req.Name,
			"scan_type": req.ScanType,
		}
		if hasStatusFilter {
			filterObj["status"] = statusValue
		}

		// Determine the actual sort field for response
		responseSortField := originalSortField
		if !isTargetSort {
			responseSortField = mapDBColumnToAPIField(mapAPIFieldToDBColumn(originalSortField))
		}

		result := map[string]interface{}{
			"data": map[string]interface{}{
				"contents": contents,
				"count":    totalCount,
			},
			"scanner": map[string]interface{}{
				"limit": limit,
				"page":  page,
				"sort": []map[string]string{
					{
						"field": responseSortField,
						"order": sortOrder,
					},
				},
				"filter": filterObj,
			},
		}

		logger.Info("Returning scanner list", "count", len(contents), "total", totalCount, "target_sort", isTargetSort)
		return c.JSON(result)
	}
}

func GetScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		id := c.Params("id")
		if id == "" {
			log.Printf("Scanner ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		log.Printf("Looking up scanner with ID: %s", id)
		response, err := srv.GetScanner(c.UserContext(), &pb.GetScannerRequest{Id: id})
		if err != nil {
			log.Printf("Error retrieving scanner: %v", err)
			if errors.Is(err, service.ErrScannerNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Scanner not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(SuccessResponse{
			Scanner: response.Scanner,
			Success: true,
		})
	}
}

func DeleteScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		id := c.Params("id")
		if id == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		_, err := srv.DeleteScanner(c.UserContext(), &pb.DeleteScannerRequest{Id: id})
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Scanner not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}

func DeleteScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.DeleteScannersRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Failed to parse request body",
			})
		}

		if len(req.Ids) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "IDs must not be empty",
			})
		}

		response, err := srv.DeleteScanners(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Success: false,
					Error:   err.Error(),
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(response)
	}
}

func UpdateScannerStatus(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())

		var req pb.UpdateScannerStatusRequest
		if err := c.BodyParser(&req); err != nil {
			logger.Error("Failed to parse request body", "error", err)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Failed to parse request body",
			})
		}

		logger.Info("Processing scanner status update request",
			"ids", req.Ids,
			"status", req.Status,
			"filter", req.Filter,
			"exclude", req.Exclude,
			"update_all", req.UpdateAll)

		response, err := srv.UpdateScannerStatus(c.UserContext(), &req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}

func RunScanNow(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		// Get scanner ID from URL parameter
		id := c.Params("id")
		if id == "" {
			log.Printf("Run scan now: Scanner ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		log.Printf("Attempting to run immediate scan for scanner with ID: %s", id)

		// Create the request
		req := &pb.RunScanNowRequest{
			ScannerId: id,
		}

		// Call the service to execute the scan
		response, err := srv.RunScanNow(c.UserContext(), req)
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Scanner not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		if !response.Success {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   response.ErrorMessage,
			})
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}

func processScheduleFields(scheduleObj map[string]interface{}, req *pb.UpdateScannerRequest) {
	// Handle schedule type
	if scheduleType, ok := scheduleObj["schedule_type"].(string); ok && scheduleType != "" {
		req.ScheduleType = scheduleType
	}

	// Handle frequency settings
	if frequencyValue, ok := scheduleObj["frequency_value"].(float64); ok {
		req.FrequencyValue = int64(frequencyValue)
	}
	if frequencyUnit, ok := scheduleObj["frequency_unit"].(string); ok && frequencyUnit != "" {
		req.FrequencyUnit = frequencyUnit
	}

	// Handle run_time
	if runTime, ok := scheduleObj["run_time"].(string); ok && runTime != "" {
		req.RunTime = runTime
	}

	// Handle specific time components
	if month, ok := scheduleObj["month"].(float64); ok {
		req.Month = int64(month)
	}
	if week, ok := scheduleObj["week"].(float64); ok {
		req.Week = int64(week)
	}
	if day, ok := scheduleObj["day"].(float64); ok {
		req.Day = int64(day)
	}
	if hour, ok := scheduleObj["hour"].(float64); ok {
		req.Hour = int64(hour)
	}
	if minute, ok := scheduleObj["minute"].(float64); ok {
		req.Minute = int64(minute)
	}
}

// extractSortParameters extracts and returns the original API field names (not mapped to DB columns)
func extractSortParameters(c *fiber.Ctx) (string, string) {
	// Default values
	sortField := "id"
	sortOrder := "desc"

	// Check for legacy format first
	if legacySortField := c.Query("sort_field"); legacySortField != "" {
		sortField = legacySortField // Return original API field, don't map yet
		sortOrder = c.Query("sort_order", "desc")
		return sortField, sortOrder
	}

	// Check for array format: sort[0][field] and sort[0][order]
	if arraySortField := c.Query("sort[0][field]"); arraySortField != "" {
		sortField = arraySortField // Return original API field, don't map yet
		sortOrder = c.Query("sort[0][order]", "desc")
		return sortField, sortOrder
	}

	// Return defaults
	return sortField, sortOrder
}

// mapAPIFieldToDBColumn maps API field names to database column names
func mapAPIFieldToDBColumn(apiField string) string {
	fieldMapping := map[string]string{
		"id":         "id",
		"name":       "name",
		"type":       "scan_type", // Maps "type" to "scan_type"
		"status":     "status",
		"created_at": "created_at",
		"updated_at": "updated_at",
		"user_id":    "user_id",
	}
	if dbColumn, exists := fieldMapping[apiField]; exists {
		return dbColumn
	}
	// Default to id if field is not recognized
	return "id"
}

// mapDBColumnToAPIField maps database column names back to API field names for response
func mapDBColumnToAPIField(dbColumn string) string {
	fieldMapping := map[string]string{
		"id":         "id",
		"name":       "name",
		"scan_type":  "type", // Maps "scan_type" back to "type"
		"status":     "status",
		"created_at": "created_at",
		"updated_at": "updated_at",
		"user_id":    "user_id",
	}
	if apiField, exists := fieldMapping[dbColumn]; exists {
		return apiField
	}
	return dbColumn
}
