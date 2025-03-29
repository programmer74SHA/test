package types

import (
	"time"
)

// ScannerModel represents a scanner in the database
type ScannerModel struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ScanType  *int       `gorm:"column:scan_type"`
	Name      string     `gorm:"column:name;size:255;not null"`
	IsActive  bool       `gorm:"column:is_active;default:1"`
	Endpoint  string     `gorm:"column:endpoint;size:255"`
	Username  string     `gorm:"column:username;size:100"`
	Password  string     `gorm:"column:password;size:255"`
	ApiKey    string     `gorm:"column:api_key;size:255"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	UserID    *string    `gorm:"column:user_id;size:100"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`
}

func (ScannerModel) TableName() string {
	return "scanners"
}

// ScannerModelFilter struct for filtering scanners
type ScannerModelFilter struct {
	Name    string
	Type    string
	Enabled *bool
}
