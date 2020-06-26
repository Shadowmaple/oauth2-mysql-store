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

type Config struct {
	Addr       string
	UserName   string
	Password   string
	Database   string
	Table      string
	GcDisabled bool
	GcInterval time.Duration
}

type TokenModel struct {
	// gorm.Model
	ID        uint      `gorm:"primary_key; AUTO_INCREMENT"`
	CreatedAt time.Time `gorm:"column:created_at"`
	ExpiredAt int64     `gorm:"column:expired_at"`
	Code      string    `gorm:"column:code; type:varchar(255); default:''"`
	Access    string    `gorm:"column:access; type:varchar(255); default:''"`
	Refresh   string    `gorm:"column:refresh; type:varchar(255); default:''"`
	Data      string    `gorm:"column:data; type:text"`
}

func DefaultConfig() *Config {
	return &Config{
		Addr:     "localhost:3306",
		UserName: "root",
		Password: "root",
		Database: "oauth2",
	}
}

func NewDefaultTokenStore() *TokenStore {
	return NewTokenStore(DefaultConfig())
}

func NewTokenStore(cf *Config) *TokenStore {
	uri := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&parseTime=True&loc=Local",
		cf.UserName, cf.Password, cf.Addr, cf.Database)

	db, err := gorm.Open("mysql", uri)
	if err != nil {
		panic(err)
	}

	store := &TokenStore{
		db:         db,
		tableName:  cf.Table,
		gcDisabled: cf.GcDisabled,
		gcInterval: cf.GcInterval,
	}
	if cf.Table == "" {
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
		if cf.GcInterval <= 0 {
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
		return
	}
	log.Printf("------- gc OK ---------- %d\n", count)
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

	var item TokenModel
	err := t.db.Table(t.tableName).Where("code = ?", code).First(&item).Error
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
	err := t.db.Table(t.tableName).Where("access = ?", access).First(&item).Error
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
	err := t.db.Table(t.tableName).Where("refresh = ?", refresh).First(&item).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, nil
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
