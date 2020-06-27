package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"gopkg.in/oauth2.v4"
	"gopkg.in/oauth2.v4/models"
)

type TokenStore struct {
	db         *gorm.DB
	tableName  string
	gcDisabled bool
	gcInterval time.Duration
	ticker     *time.Ticker
}

type TokenModel struct {
	ID        uint64    `gorm:"primary_key; AUTO_INCREMENT"`
	CreatedAt time.Time `gorm:"column:created_at"`
	ExpiredAt int64     `gorm:"column:expired_at"`
	Code      string    `gorm:"column:code; type:varchar(255); default:''"`
	Access    string    `gorm:"column:access; type:varchar(255); default:''"`
	Refresh   string    `gorm:"column:refresh; type:varchar(255); default:''"`
	Data      string    `gorm:"column:data; type:text"`
}

func NewDefaultTokenStore() *TokenStore {
	return NewTokenStore(DefaultTokenConfig())
}

func NewTokenStore(cfg *TokenConfig) *TokenStore {
	uri := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&parseTime=True&loc=Local",
		cfg.UserName, cfg.Password, cfg.Addr, cfg.Database)

	db, err := gorm.Open("mysql", uri)
	if err != nil {
		panic(err)
	}

	store := &TokenStore{
		db:         db,
		tableName:  cfg.Table,
		gcDisabled: cfg.GcDisabled,
		gcInterval: cfg.GcInterval,
	}
	if cfg.Table == "" {
		store.tableName = "oauth2_token"
	}

	// Create table if not exists.
	if !db.HasTable(store.tableName) {
		err := db.Table(store.tableName).CreateTable(&TokenModel{}).Error
		if err != nil {
			panic(err)
		}
	}

	if !store.gcDisabled {
		if cfg.GcInterval <= 0 {
			store.gcInterval = time.Minute * 30
		}
		store.ticker = time.NewTicker(store.gcInterval)

		go store.gc()
	}

	return store
}

func (t *TokenStore) Close() {
	if !t.gcDisabled {
		t.ticker.Stop()
	}
	t.db.Close()
}

func (t *TokenStore) gc() {
	for range t.ticker.C {
		t.clean()
	}
}

func (t *TokenStore) clean() {
	now := time.Now().Unix()
	var count int32
	var err error

	err = t.db.Table(t.tableName).
		Where("expired_at <= ?", now).
		Or("code = '' AND access = '' AND refresh = ''").Count(&count).Error

	if err != nil {
		log.Println(err)
		return
	}
	if count == 0 {
		return
	}

	err = t.db.Table(t.tableName).
		Where("expired_at <= ?", now).
		Or("code = '' AND access = '' AND refresh = ''").Delete(&TokenModel{}).Error

	if err != nil {
		log.Println(err)
	}
}

// create and store the new token information
func (t *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	item := &TokenModel{
		Data: string(data),
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

	return t.db.Table(t.tableName).Create(item).Error
}

// delete the authorization code
func (t *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return t.db.Table(t.tableName).Where("code = ?", code).Update("code", "").Error
}

// use the access token to delete the token information
func (t *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return t.db.Table(t.tableName).Where("access = ?", access).Update("access", "").Error
}

// use the refresh token to delete the token information
func (t *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return t.db.Table(t.tableName).Where("refresh = ?", refresh).Update("refresh", "").Error
}

// use the authorization code for token information data
func (t *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	var item struct{ Data string }
	err := t.db.Table(t.tableName).Select("data").Where("code = ?", code).Scan(&item).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return t.parseTokenData(item.Data)
}

// use the access token for token information data
func (t *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	var item struct{ Data string }
	err := t.db.Table(t.tableName).Select("data").Where("access = ?", access).Scan(&item).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return t.parseTokenData(item.Data)
}

// use the refresh token for token information data
func (t *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	var item struct{ Data string }
	err := t.db.Table(t.tableName).Select("data").Where("refresh = ?", refresh).Scan(&item).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return t.parseTokenData(item.Data)
}

// parseTokenData parse token data from json string to oauth2.TokenInfo.
func (t *TokenStore) parseTokenData(data string) (oauth2.TokenInfo, error) {
	var info models.Token
	if err := json.Unmarshal([]byte(data), &info); err != nil {
		return nil, err
	}
	return &info, nil
}
