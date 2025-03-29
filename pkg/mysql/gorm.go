package mysql

import (
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBConnOptions struct {
	Host     string
	Port     uint
	Username string
	Password string
	Database string
}

func NewMysqlConnection(cfg DBConnOptions) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
	)
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

// GormMigrations manually creates all required tables with proper order
func GormMigrations(db *gorm.DB) {
	// Disable foreign key checks during migration
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1") // Re-enable after migration

	// SQL statements for table creation in proper order
	sqlStatements := []string{
		// Create users table
		`CREATE TABLE IF NOT EXISTS users (
			user_id VARCHAR(100) PRIMARY KEY,
			first_name VARCHAR(100),
			last_name VARCHAR(100),
			username VARCHAR(100) NOT NULL,
			password VARCHAR(200) NOT NULL,
			email VARCHAR(100),
			role VARCHAR(100) NOT NULL DEFAULT 'user',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			deleted_at DATETIME,
			UNIQUE INDEX idx_users_username (username)
		)`,

		// Create sessions table
		`CREATE TABLE IF NOT EXISTS sessions (
			user_id VARCHAR(100) NOT NULL,
			access_token VARCHAR(200) NOT NULL,
			refresh_token VARCHAR(200) NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			is_login BOOLEAN DEFAULT TRUE,
			PRIMARY KEY (refresh_token),
			UNIQUE INDEX idx_sessions_access_token (access_token),
			INDEX idx_sessions_user_id (user_id),
			CONSTRAINT fk_sessions_user FOREIGN KEY (user_id)
				REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create scanners table
		`CREATE TABLE IF NOT EXISTS scanners (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			scan_type INT,
			name VARCHAR(255) NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			endpoint VARCHAR(255),
			api_key VARCHAR(255),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			user_id VARCHAR(100),
			deleted_at DATETIME,
			INDEX idx_scanners_user_id (user_id),
			CONSTRAINT fk_scanners_user FOREIGN KEY (user_id)
				REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE
		)`,

		// Create assets table
		`CREATE TABLE IF NOT EXISTS assets (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(50),
			domain VARCHAR(50),
			hostname VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			mac_address VARCHAR(17),
			os_name VARCHAR(100),
			os_version VARCHAR(50),
			asset_type ENUM('Physical', 'Virtual', 'Unknown') NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			deleted_at DATETIME,
			UNIQUE INDEX idx_assets_ip_address (ip_address)
		)`,

		// Create ports table
		`CREATE TABLE IF NOT EXISTS ports (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			asset_id BIGINT NOT NULL,
			port_number INT NOT NULL,
			protocol ENUM('TCP', 'UDP') NOT NULL,
			state ENUM('Open', 'Closed', 'Filtered') NOT NULL,
			service_name VARCHAR(100),
			service_version VARCHAR(100),
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_ports_asset_id (asset_id),
			CONSTRAINT fk_ports_asset FOREIGN KEY (asset_id)
				REFERENCES assets(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create vmware_vms table
		`CREATE TABLE IF NOT EXISTS vmware_vms (
			vm_id BIGINT AUTO_INCREMENT PRIMARY KEY,
			asset_id BIGINT NOT NULL,
			vm_name VARCHAR(255) NOT NULL,
			hypervisor VARCHAR(100) NOT NULL,
			cpu_count INT NOT NULL,
			memory_mb INT NOT NULL,
			disk_size_gb INT NOT NULL,
			power_state ENUM('On', 'Off', 'Suspended') NOT NULL,
			last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_vmware_vms_asset_id (asset_id),
			CONSTRAINT fk_vmware_vms_asset FOREIGN KEY (asset_id)
				REFERENCES assets(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create scan_jobs table
		`CREATE TABLE IF NOT EXISTS scan_jobs (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(50) NOT NULL,
			type VARCHAR(50) NOT NULL,
			status ENUM('Pending', 'Running', 'Completed', 'Failed', 'Error') NOT NULL DEFAULT 'Pending',
			end_datetime DATETIME,
			start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			end_time DATETIME,
			progress INT,
			scanner_id BIGINT NOT NULL,
			INDEX idx_scan_jobs_scanner_id (scanner_id),
			CONSTRAINT fk_scan_jobs_scanner FOREIGN KEY (scanner_id)
				REFERENCES scanners(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create asset_scan_jobs table
		`CREATE TABLE IF NOT EXISTS asset_scan_jobs (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			asset_id BIGINT NOT NULL,
			scan_job_id BIGINT NOT NULL,
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE INDEX idx_asset_job_unique (asset_id, scan_job_id),
			INDEX idx_asset_scan_jobs_asset_id (asset_id),
			INDEX idx_asset_scan_jobs_scan_job_id (scan_job_id),
			CONSTRAINT fk_asset_scan_jobs_asset FOREIGN KEY (asset_id)
				REFERENCES assets(id) ON DELETE CASCADE ON UPDATE CASCADE,
			CONSTRAINT fk_asset_scan_jobs_scan_job FOREIGN KEY (scan_job_id)
				REFERENCES scan_jobs(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create nmap_metadatas table
		`CREATE TABLE IF NOT EXISTS nmap_metadatas (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			scanner_id BIGINT NOT NULL,
			type ENUM('Top Port', 'Default') NOT NULL,
			target ENUM('IP', 'Network', 'Range') NOT NULL,
			UNIQUE INDEX idx_nmap_metadatas_unique (scanner_id),
			CONSTRAINT fk_nmap_metadatas_scanner FOREIGN KEY (scanner_id)
				REFERENCES scanners(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create nmap_ip_scan table
		`CREATE TABLE IF NOT EXISTS nmap_ip_scan (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			nmap_metadatas_id BIGINT NOT NULL,
			ip VARCHAR(50) NOT NULL,
			UNIQUE INDEX idx_nmap_ip_scan_unique (nmap_metadatas_id),
			CONSTRAINT fk_nmap_ip_scan_metadata FOREIGN KEY (nmap_metadatas_id)
				REFERENCES nmap_metadatas(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create nmap_network_scan table
		`CREATE TABLE IF NOT EXISTS nmap_network_scan (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			nmap_metadatas_id BIGINT NOT NULL,
			ip VARCHAR(50) NOT NULL,
			subnet INT NOT NULL,
			UNIQUE INDEX idx_nmap_network_scan_unique (nmap_metadatas_id),
			CONSTRAINT fk_nmap_network_scan_metadata FOREIGN KEY (nmap_metadatas_id)
				REFERENCES nmap_metadatas(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create nmap_range_scan table
		`CREATE TABLE IF NOT EXISTS nmap_range_scan (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			nmap_metadatas_id BIGINT NOT NULL,
			start_ip VARCHAR(50) NOT NULL,
			end_ip VARCHAR(50) NOT NULL,
			UNIQUE INDEX idx_nmap_range_scan_unique (nmap_metadatas_id),
			CONSTRAINT fk_nmap_range_scan_metadata FOREIGN KEY (nmap_metadatas_id)
				REFERENCES nmap_metadatas(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create domain_metadata table
		`CREATE TABLE IF NOT EXISTS domain_metadata (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			scanner_id BIGINT NOT NULL,
			ip VARCHAR(50) NOT NULL,
			port VARCHAR(50) NOT NULL,
			domain VARCHAR(50) NOT NULL,
			username VARCHAR(50) NOT NULL,
			password VARCHAR(50) NOT NULL,
			authentication_type VARCHAR(50) NOT NULL,
			protocol VARCHAR(50) NOT NULL,
			CONSTRAINT fk_domain_metadata_scanner FOREIGN KEY (scanner_id)
				REFERENCES scanners(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create vcenter_metadata table
		`CREATE TABLE IF NOT EXISTS vcenter_metadata (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			scanner_id BIGINT NOT NULL,
			ip VARCHAR(50) NOT NULL,
			port VARCHAR(50) NOT NULL,
			username VARCHAR(50) NOT NULL,
			password VARCHAR(50) NOT NULL,
			CONSTRAINT fk_vcenter_metadata_scanner FOREIGN KEY (scanner_id)
				REFERENCES scanners(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,

		// Create schedules table
		`CREATE TABLE IF NOT EXISTS schedules (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			frequency_value INT NOT NULL DEFAULT 1,
			frequency_unit VARCHAR(50) NOT NULL,
			month INT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			scanner_id BIGINT NOT NULL,
			week INT,
			day INT,
			hour INT,
			minute INT,
			INDEX idx_schedules_scanner_id (scanner_id),
			CONSTRAINT fk_schedules_scanner FOREIGN KEY (scanner_id)
				REFERENCES scanners(id) ON DELETE CASCADE ON UPDATE CASCADE
		)`,
	}

	// Execute each SQL statement
	for i, sqlStmt := range sqlStatements {
		tableName := fmt.Sprintf("Table %d", i+1)
		if i == 0 {
			tableName = "users"
		} else if i == 1 {
			tableName = "sessions"
		} else if i == 2 {
			tableName = "scanners"
		} else if i == 3 {
			tableName = "assets"
		}

		fmt.Printf("Creating table: %s\n", tableName)
		if err := db.Exec(sqlStmt).Error; err != nil {
			log.Fatalf("Failed to create table %s: %v", tableName, err)
		}
	}

	fmt.Println("Migration completed successfully!")
}

// Optional: Add a function to create a database if it doesn't exist
func CreateDatabaseIfNotExists(cfg DBConnOptions) error {
	// Connect to MySQL without specifying a database
	dsnNoDb := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
	)

	db, err := gorm.Open(mysql.Open(dsnNoDb), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL: %v", err)
	}

	// Create the database if it doesn't exist
	createDbSQL := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", cfg.Database)
	if err := db.Exec(createDbSQL).Error; err != nil {
		return fmt.Errorf("failed to create database: %v", err)
	}

	fmt.Printf("Database '%s' created or already exists\n", cfg.Database)
	return nil
}

// Optional: Add a function to drop a database (useful for testing)
func DropDatabase(cfg DBConnOptions) error {
	// Connect to MySQL without specifying a database
	dsnNoDb := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
	)

	db, err := gorm.Open(mysql.Open(dsnNoDb), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL: %v", err)
	}

	// Drop the database if it exists
	dropDbSQL := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", cfg.Database)
	if err := db.Exec(dropDbSQL).Error; err != nil {
		return fmt.Errorf("failed to drop database: %v", err)
	}

	fmt.Printf("Database '%s' dropped if it existed\n", cfg.Database)
	return nil
}
