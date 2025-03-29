package mysql

import (
	"fmt"
	"log"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
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

func GormMigrations(db *gorm.DB) {
	// Models to migrate - ordered to respect foreign key dependencies
	models := []interface{}{
		&types.User{},            // No foreign key dependencies - must be first for Session
		&types.Asset{},           // No foreign key dependencies
		&types.Scanner{},         // Has optional UserID reference
		&types.ScanJob{},         // Depends on Scanner
		&types.Port{},            // Depends on Asset
		&types.VMwareVM{},        // Depends on Asset
		&types.AssetScanJob{},    // Depends on Asset and ScanJob
		&types.NmapMetadata{},    // Depends on Scanner
		&types.NmapIPScan{},      // Depends on NmapMetadata
		&types.NmapNetworkScan{}, // Depends on NmapMetadata
		&types.NmapRangeScan{},   // Depends on NmapMetadata
		&types.DomainMetadata{},  // Depends on Scanner
		&types.VCenterMetadata{}, // Depends on Scanner
		&types.Schedule{},        // Depends on Scanner
		&types.Session{},         // Depends on User (must be after User)
	}

	// Run migration
	fmt.Println("Starting migration...")
	for _, model := range models {
		fmt.Printf("Migrating %T...\n", model)
		if err := db.AutoMigrate(model); err != nil {
			log.Fatalf("Failed to migrate %T: %v", model, err)
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
