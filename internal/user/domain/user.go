package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/conv"
	"github.com/google/uuid"
)

type UserUUID = uuid.UUID

type User struct {
	ID        UserUUID
	FirstName string
	LastName  string
	Username  string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

type UserFilter struct {
	FirstName string
	LastName  string
	Username  string
}

type Sessions struct {
	UserID       UserUUID
	AccessToken  string
	RefreshToken string
	IsLogin      bool
	CreatedAt    time.Time
	// ExpiresAt    time.Time
}

func UserUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func (u *User) PasswordIsCorrect(pass string) bool {
	return NewPassword(pass) == u.Password
}

func NewPassword(pass string) string {
	h := sha256.New()
	h.Write(conv.ToBytes(pass))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
