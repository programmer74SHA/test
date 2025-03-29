package types

import (
	"time"
)

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

	// Scanner  Scanner   `gorm:"foreignKey:UserID"`
	Sessions []Session `gorm:"foreignKey:UserID"`
}

type UserFilter struct {
	FirstName string
	LastName  string
	Username  string
}

type Session struct {
	UserID       string    `gorm:"column:user_id;size:100;not null"`
	AccessToken  string    `gorm:"column:access_token;size:200;not null;uniqueIndex"`
	RefreshToken string    `gorm:"column:refresh_token;size:200;not null;primaryKey"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null"`
	IsLogin      bool      `gorm:"column:is_login;default:1"`

	// User User `gorm:"foreignKey:UserID"`
}
