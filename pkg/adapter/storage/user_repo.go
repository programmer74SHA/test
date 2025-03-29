package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type userRepo struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) port.Repo {
	return &userRepo{
		db: db,
	}
}

func (r *userRepo) Create(ctx context.Context, user domain.User) (domain.UserUUID, error) {
	u := mapper.UserDomain2Storage(user)
	userID, err := uuid.Parse(u.UserID)
	if err != nil {
		// TODO error handling
		panic("cannot pars uuid")
	}
	return userID, r.db.Table("users").WithContext(ctx).Create(&u).Error
}

func (r *userRepo) GetByUsername(ctx context.Context, filter domain.UserFilter) (*domain.User, error) {
	uf := mapper.UserFilterDomain2Storage(filter)
	var user domain.User
	q := r.db.Table("users").Debug().WithContext(ctx)
	if len(uf.FirstName) > 0 {
		q.Where("first_name = ?", uf.FirstName)
	}

	if len(uf.LastName) > 0 {
		q.Where("last_name = ?", uf.LastName)
	}

	if len(uf.Username) > 0 {
		q.Where("username = ?", uf.Username)
	}

	err := q.First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) StoreSession(ctx context.Context, session domain.Sessions) error {
	s := mapper.UserSessionDomain2Storage(session)
	return r.db.Table("sessions").WithContext(ctx).Create(&s).Error
}

func (r *userRepo) InvalidateSession(ctx context.Context, refreshToken string) error {
	result := r.db.WithContext(ctx).Table("sessions").Where("refresh_token = ?", refreshToken).Update("is_login", false)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("session not found")
	}
	return nil
}
