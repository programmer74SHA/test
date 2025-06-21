package storage_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormMysql "gorm.io/driver/mysql"
	"gorm.io/gorm"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
)

type AssetRepoTestSuite struct {
	db     *sql.DB
	gormDB *gorm.DB
	mock   sqlmock.Sqlmock
	repo   assetPort.Repo
	ctx    context.Context
}

func setupAssetRepoTest(t *testing.T) *AssetRepoTestSuite {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(gormMysql.New(gormMysql.Config{
		Conn:                      db,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	require.NoError(t, err)

	repo := storage.NewAssetRepo(gormDB)
	ctx := context.Background()

	return &AssetRepoTestSuite{
		db:     db,
		gormDB: gormDB,
		mock:   mock,
		repo:   repo,
		ctx:    ctx,
	}
}

func (suite *AssetRepoTestSuite) tearDown() {
	suite.db.Close()
}

func TestAssetRepository_Create_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query first (must return 0 for no duplicates)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the asset INSERT - GORM fields in actual order
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			&assetDomain.Risk,
			&assetDomain.LoggingCompleted,
			&assetDomain.AssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DuplicateHostname(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query to return 1 (duplicate exists)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DatabaseConnectionError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock database connection error on hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(sql.ErrConnDone)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithAssetIPs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.100", "10.0.0.50"})

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the IP existence check that happens when there are IPs
	suite.mock.ExpectQuery("SELECT \\* FROM `asset_ips` WHERE ip_address IN \\(\\?\\,\\?\\)").
		WithArgs("192.168.1.100", "10.0.0.50").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock asset insert
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			&assetDomain.Risk,
			&assetDomain.LoggingCompleted,
			&assetDomain.AssetValue,
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // deleted_at
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock asset IP inserts
	for range assetDomain.AssetIPs {
		suite.mock.ExpectExec("INSERT INTO `asset_ips`").
			WithArgs(
				sqlmock.AnyArg(),
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // IP
				sqlmock.AnyArg(),        // MACAddress
				sqlmock.AnyArg(),        // CreatedAt
				sqlmock.AnyArg(),        // UpdatedAt
				sqlmock.AnyArg(),        // DeletedAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithPorts(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithPorts(3)

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock asset insert
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			&assetDomain.Risk,
			&assetDomain.LoggingCompleted,
			&assetDomain.AssetValue,
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // deleted_at
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock port inserts - based on actual Port structure in types
	for range assetDomain.Ports {
		suite.mock.ExpectExec("INSERT INTO `ports`").
			WithArgs(
				sqlmock.AnyArg(),        // ID
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // PortNumber
				sqlmock.AnyArg(),        // Protocol
				sqlmock.AnyArg(),        // State
				sqlmock.AnyArg(),        // ServiceName (pointer)
				sqlmock.AnyArg(),        // ServiceVersion (pointer)
				sqlmock.AnyArg(),        // Description (pointer)
				sqlmock.AnyArg(),        // DeletedAt (pointer)
				sqlmock.AnyArg(),        // DiscoveredAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_InvalidAssetData(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	assetDomain.Hostname = "" // Invalid empty hostname

	// Mock hostname check (empty hostname won't match)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction and constraint violation
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WillReturnError(&mysql.MySQLError{Number: 1048, Message: "Column 'hostname' cannot be null"})
	suite.mock.ExpectRollback()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be null")
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_ContextCancellation(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock context cancellation error during the hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(context.Canceled)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}
