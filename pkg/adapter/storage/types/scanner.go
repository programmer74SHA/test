package types

import (
	"time"
)

type Scanner struct {
	ScannerID   string     `gorm:"column:scanner_id;primaryKey;size:100"`
	Name        string     `gorm:"column:name;size:100;not null"`
	Type        string     `gorm:"column:type;size:50;not null"`
	Description *string    `gorm:"column:description;size:500"`
	Endpoint    string     `gorm:"column:endpoint;size:255;not null"`
	Username    *string    `gorm:"column:username;size:100"`
	Password    *string    `gorm:"column:password;size:255"`
	APIKey      *string    `gorm:"column:api_key;size:255"`
	Enabled     bool       `gorm:"column:enabled;default:true"`
	CreatedAt   time.Time  `gorm:"column:created_at;type:datetime;not null"`
	UpdatedAt   *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt   *time.Time `gorm:"column:deleted_at;type:datetime"`
}

type ScannerFilter struct {
	Name    string
	Type    string
	Enabled *bool
}
