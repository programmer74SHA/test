package types

import "time"

// Asset represents an asset in the system
type Asset struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Name       *string    `gorm:"column:name;size:50"`
	Domain     *string    `gorm:"column:domain;size:50"`
	Hostname   string     `gorm:"column:hostname;size:255;not null"`
	IPAddress  string     `gorm:"column:ip_address;size:45;not null;uniqueIndex"`
	MACAddress *string    `gorm:"column:mac_address;size:17"`
	OSName     *string    `gorm:"column:os_name;size:100"`
	OSVersion  *string    `gorm:"column:os_version;size:50"`
	AssetType  string     `gorm:"column:asset_type;type:enum('Physical','Virtual','Unknown');not null"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt  *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt  *time.Time `gorm:"column:deleted_at;type:datetime"`

	Ports         []Port         `gorm:"foreignKey:AssetID"`
	VMwareVMs     []VMwareVM     `gorm:"foreignKey:AssetID"`
	AssetScanJobs []AssetScanJob `gorm:"foreignKey:AssetID"`
}

func (Asset) TableName() string {
	return "assets"
}

type Port struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID        int64     `gorm:"column:asset_id;not null"`
	PortNumber     int       `gorm:"column:port_number;not null"`
	Protocol       string    `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string    `gorm:"column:state;type:enum('Open','Closed','Filtered');not null"`
	ServiceName    *string   `gorm:"column:service_name;size:100"`
	ServiceVersion *string   `gorm:"column:service_version;size:100"`
	DiscoveredAt   time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

func (Port) TableName() string {
	return "ports"
}

type Scanner struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ScanType  *int       `gorm:"column:scan_type"`
	Name      string     `gorm:"column:name;size:255;not null"`
	IsActive  bool       `gorm:"column:is_active;default:1"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	UserID    *string    `gorm:"column:user_id;size:100"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	NmapMetadatas    []NmapMetadata    `gorm:"foreignKey:ScannerID"`
	DomainMetadatas  []DomainMetadata  `gorm:"foreignKey:ScannerID"`
	VCenterMetadatas []VCenterMetadata `gorm:"foreignKey:ScannerID"`
	Schedules        []Schedule        `gorm:"foreignKey:ScannerID"`
	ScanJob          ScanJob           `gorm:"foreignKey:ScannerID"`
}

func (Scanner) TableName() string {
	return "scanners"
}

type ScanJob struct {
	ID          int64      `gorm:"column:id;primaryKey;autoIncrement"`
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

func (ScanJob) TableName() string {
	return "scan_jobs"
}

type AssetScanJob struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID      int64     `gorm:"column:asset_id;not null;uniqueIndex:asset_job_unique"`
	ScanJobID    int64     `gorm:"column:scan_job_id;not null;uniqueIndex:asset_job_unique"`
	DiscoveredAt time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset   Asset   `gorm:"foreignKey:AssetID"`
	ScanJob ScanJob `gorm:"foreignKey:ScanJobID"`
}

func (AssetScanJob) TableName() string {
	return "asset_scan_jobs"
}

type VMwareVM struct {
	VMID         int64     `gorm:"column:vm_id;primaryKey;autoIncrement"`
	AssetID      int64     `gorm:"column:asset_id;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int       `gorm:"column:cpu_count;not null"`
	MemoryMB     int       `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

func (VMwareVM) TableName() string {
	return "vmware_vms"
}

type NmapMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID int64  `gorm:"column:scanner_id;not null;uniqueIndex:nmap_metadatas_unique"`
	Type      string `gorm:"column:type;type:enum('Top Port','Default');not null"`
	Target    string `gorm:"column:target;type:enum('IP','Network','Range');not null"`

	Scanner     Scanner          `gorm:"foreignKey:ScannerID"`
	IPScan      *NmapIPScan      `gorm:"foreignKey:NmapMetadatasID"`
	NetworkScan *NmapNetworkScan `gorm:"foreignKey:NmapMetadatasID"`
	RangeScan   *NmapRangeScan   `gorm:"foreignKey:NmapMetadatasID"`
}

func (NmapMetadata) TableName() string {
	return "nmap_metadatas"
}

type NmapIPScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_ip_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

func (NmapIPScan) TableName() string {
	return "nmap_ip_scan"
}

type NmapNetworkScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_network_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`
	Subnet          int    `gorm:"column:subnet;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

func (NmapNetworkScan) TableName() string {
	return "nmap_network_scan"
}

type NmapRangeScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_range_scan_unique"`
	StartIP         string `gorm:"column:start_ip;size:50;not null"`
	EndIP           string `gorm:"column:end_ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

func (NmapRangeScan) TableName() string {
	return "nmap_range_scan"
}

type DomainMetadata struct {
	ID                 int64  `gorm:"column:id;primaryKey"`
	ScannerID          int64  `gorm:"column:scanner_id;not null"`
	IP                 string `gorm:"column:ip;size:50;not null"`
	Port               string `gorm:"column:port;size:50;not null"`
	Domain             string `gorm:"column:domain;size:50;not null"`
	Username           string `gorm:"column:username;size:50;not null"`
	Password           string `gorm:"column:password;size:50;not null"`
	AuthenticationType string `gorm:"column:authentication_type;size:50;not null"`
	Protocol           string `gorm:"column:protocol;size:50;not null"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

func (DomainMetadata) TableName() string {
	return "domain_metadata"
}

type VCenterMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	ScannerID int64  `gorm:"column:scanner_id;not null"`
	IP        string `gorm:"column:ip;size:50;not null"`
	Port      string `gorm:"column:port;size:50;not null"`
	Username  string `gorm:"column:username;size:50;not null"`
	Password  string `gorm:"column:password;size:50;not null"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

func (VCenterMetadata) TableName() string {
	return "vcenter_metadata"
}

type Schedule struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	FrequencyValue int        `gorm:"column:frequency_value;not null;default:1"`
	FrequencyUnit  string     `gorm:"column:frequency_unit;size:50;not null"`
	Month          *int       `gorm:"column:month"`
	CreatedAt      time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt      *time.Time `gorm:"column:updated_at;type:datetime"`
	ScannerID      int64      `gorm:"column:scanner_id;not null"`
	Week           *int       `gorm:"column:week"`
	Day            *int       `gorm:"column:day"`
	Hour           *int       `gorm:"column:hour"`
	Minute         *int       `gorm:"column:minute"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

func (Schedule) TableName() string {
	return "schedules"
}

type User struct {
	UserID    string     `gorm:"column:user_id;primaryKey;size:100"`
	FirstName *string    `gorm:"column:first_name;size:100"`
	LastName  *string    `gorm:"column:last_name;size:100"`
	Username  string     `gorm:"column:username;size:100;not null;uniqueIndex:users_unique"`
	Password  string     `gorm:"column:password;size:200;not null"`
	Email     *string    `gorm:"column:email;size:100"`
	Role      string     `gorm:"column:role;size:100;not null"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;not null"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	Sessions []Session `gorm:"foreignKey:UserID"`
}

func (User) TableName() string {
	return "users"
}

type Session struct {
	UserID       string    `gorm:"column:user_id;size:100;not null"`
	AccessToken  string    `gorm:"column:access_token;size:200;not null;uniqueIndex"`
	RefreshToken string    `gorm:"column:refresh_token;size:200;not null;primaryKey"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null"`
	IsLogin      bool      `gorm:"column:is_login;default:1"`
}

func (Session) TableName() string {
	return "sessions"
}

// ScannerFilter struct for filtering scanners
type ScannerFilter struct {
	Name    string
	Type    string
	Enabled *bool
}

// UserFilter struct for filtering users
type UserFilter struct {
	FirstName string
	LastName  string
	Username  string
}
