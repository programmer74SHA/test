package types

import "time"

type Asset struct {
	ID          string     `gorm:"column:id;primaryKey;autoIncrement"`
	Name        *string    `gorm:"column:name;size:50"`
	Domain      *string    `gorm:"column:domain;size:50"`
	Hostname    string     `gorm:"column:hostname;size:255;not null"`
	IPAddress   string     `gorm:"column:ip_address;size:45;not null;uniqueIndex"`
	MACAddress  *string    `gorm:"column:mac_address;size:17"`
	OSName      *string    `gorm:"column:os_name;size:100"`
	OSVersion   *string    `gorm:"column:os_version;size:50"`
	Description *string    `gorm:"column:description;size:500"`
	Type        string     `gorm:"column:asset_type;type:enum('Physical','Virtual','Unknown');not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt   *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt   *time.Time `gorm:"column:deleted_at;type:datetime"`

	Ports         []Port         `gorm:"foreignKey:AssetID"`
	VMwareVMs     []VMwareVM     `gorm:"foreignKey:AssetID"`
	AssetScanJobs []AssetScanJob `gorm:"foreignKey:AssetID"`
}

type Port struct {
	ID             string    `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID        string    `gorm:"column:asset_id;size:36;not null"`
	PortNumber     int       `gorm:"column:port_number;not null"`
	Protocol       string    `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string    `gorm:"column:state;type:enum('Open','Closed','Filtered');not null"`
	ServiceName    *string   `gorm:"column:service_name;size:100"`
	ServiceVersion *string   `gorm:"column:service_version;size:100"`
	DiscoveredAt   time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

type VMwareVM struct {
	VMID         string    `gorm:"column:vm_id;primaryKey;autoIncrement"`
	AssetID      string    `gorm:"column:asset_id;size:36;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int       `gorm:"column:cpu_count;not null"`
	MemoryMB     int       `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

type AssetScanJob struct {
	ID           string    `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID      string    `gorm:"column:asset_id;size:36;not null;uniqueIndex:asset_job_unique"`
	ScanJobID    string    `gorm:"column:scan_job_id;size:36;not null;uniqueIndex:asset_job_unique"`
	DiscoveredAt time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset   Asset   `gorm:"foreignKey:AssetID"`
	ScanJob ScanJob `gorm:"foreignKey:ScanJobID"`
}

type ScanJob struct {
	ID          string     `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string     `gorm:"column:name;size:50;not null"`
	Type        string     `gorm:"column:type;size:50;not null"`
	Status      string     `gorm:"column:status;type:enum('Pending','Running','Completed','Failed','Error');not null;default:Pending"`
	EndDatetime *time.Time `gorm:"column:end_datetime;type:datetime"`
	StartTime   time.Time  `gorm:"column:start_time;type:datetime;default:CURRENT_TIMESTAMP"`
	EndTime     *time.Time `gorm:"column:end_time;type:datetime"`
	Progress    *int       `gorm:"column:progress"`
	ScannerID   int64      `gorm:"column:scanner_id;not null"`

	AssetScanJobs []AssetScanJob `gorm:"foreignKey:ScanJobID"`
}
