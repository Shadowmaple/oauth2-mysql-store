package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jinzhu/gorm"
	"gopkg.in/oauth2.v4"
)

type TokenStore struct {
	db    *gorm.DB
	table string
}

type Config struct {
	Addr     string
	User     string
	Password string
	Database string
	Table    string
}

type TokenModel struct {
	gorm.Model
	ExpiredAt int64  `gorm:"column:expired_at"`
	Code      string `gorm:"column:code type:varchar(255)"`
	Access    string `gorm:"column:access type:varchar(255)"`
	Refresh   string `gorm:"column:refresh type:varchar(255)"`
	Data      string `gorm:"column:data type:text"`
}

func DefaultConfig() *Config {
	return &Config{
		Addr:     "localhost:6844",
		User:     "root",
		Password: "root",
		Database: "oauth",
		Table:    "",
	}
}

func NewDefaultTokenStore() oauth2.TokenStore {
	return NewTokenStore(DefaultConfig())
}

func NewTokenStore(cf *Config) oauth2.TokenStore {
	uri := fmt.Sprintf("%s:%s@%s&%s", cf.User, cf.Password, cf.Addr, cf.Database)
	db, err := gorm.Open(uri)
	if err != nil {
		panic(err)
	}
	store := &TokenStore{
		db:    db,
		table: cf.Table,
	}
	if cf.Table == "" {
		store.table = "oauth_token"
	}

	if !db.HasTable(store.table) {
		err := db.Table(store.table).CreateTable(&TokenModel{}).Error
		if err != nil {
			panic(err)
		}
	}
	return store
}

// create and store the new token information
func (t *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}
	item := &TokenModel{
		Data: string(jv),
	}

	if code := info.GetCode(); code != "" {
		item.Code = code
		item.ExpiredAt = info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).Unix()
	} else {
		item.Access = info.GetAccess()
		item.ExpiredAt = info.GetAccessCreateAt().Add(info.GetAccessExpiresIn()).Unix()

		if refresh := info.GetRefresh(); refresh != "" {
			item.Refresh = info.GetRefresh()
			item.ExpiredAt = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Unix()
		}
	}

	return t.db.Table(t.table).Create(item).Error
}

// delete the authorization code
func (t *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return t.db.Table(t.table).Where("code = ?", code).Update("code", "").Error
}

// use the access token to delete the token information
func (t *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return t.db.Table(t.table).Where("access = ?", access).Update("access", "").Error
}

// use the refresh token to delete the token information
func (t *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return t.db.Table(t.table).Where("refresh = ?", refresh).Update("refresh", "").Error
}

func (t *TokenStore) parseTokenData(data string) (oauth2.TokenInfo, error) {
	var info oauth2.TokenInfo
	if err := json.Unmarshal([]byte(data), &info); err != nil {
		return nil, err
	}
	return info, nil
}

// use the authorization code for token information data
func (t *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	var item TokenModel
	err := t.db.Table(t.table).Where("code = ?", code).First(&item).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
	}

	return t.parseTokenData(item.Data)
}

// use the access token for token information data
func (t *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	var item TokenModel
	err := t.db.Table(t.table).Where("access = ?", access).First(&item).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
	}
	return t.parseTokenData(item.Data)
}

// use the refresh token for token information data
func (t *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	var item TokenModel
	err := t.db.Table(t.table).Where("refresh = ?", refresh).First(&item).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
	}

	return t.parseTokenData(item.Data)
}
