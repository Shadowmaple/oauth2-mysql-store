package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"gopkg.in/oauth2.v4"
	"gopkg.in/oauth2.v4/models"
)

type ClientStore struct {
	db        *gorm.DB
	tableName string
}

type ClientModel struct {
	ID        string    `gorm:"column:id; primary_key; type:varchar(255)"`
	Secret    string    `gorm:"column:client_secret; type:varchar(255)"`
	Domain    string    `gorm:"column:domain; type:varchar(50); index"`
	Data      string    `gorm:"column:data; type:text"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

// NewDefaultClientStore return a default client storage according to default config.
func NewDefaultClientStore() *ClientStore {
	return NewClientStore(DefaultClientConfig())
}

// NewClientStore return a new client storage.
func NewClientStore(cfg *ClientConfig) *ClientStore {
	uri := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&parseTime=True&loc=Local",
		cfg.UserName, cfg.Password, cfg.Addr, cfg.Database)

	db, err := gorm.Open("mysql", uri)
	if err != nil {
		panic(err)
	}

	store := &ClientStore{
		db:        db,
		tableName: cfg.Table,
	}
	if cfg.Table == "" {
		store.tableName = "oauth2_client"
	}

	// Create table if not exists.
	if !store.db.HasTable(store.tableName) {
		err := db.Table(store.tableName).CreateTable(&ClientModel{}).Error
		if err != nil {
			panic(err)
		}
	}

	return store
}

func (c *ClientStore) Close() {
	c.db.Close()
}

// GetByID gets client information by the ID.
func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	if id == "" {
		return nil, nil
	}

	var item struct{ Data string }
	err := c.db.Table(c.tableName).Select("data").Where("id = ?", id).Scan(&item).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return c.parseClientData(item.Data)
}

// parseClientData parses token data from json string to oauth2.TokenInfo.
func (c *ClientStore) parseClientData(data string) (oauth2.ClientInfo, error) {
	var info models.Client
	if err := json.Unmarshal([]byte(data), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Create creates a new storage record for client information.
func (c *ClientStore) Create(info oauth2.ClientInfo) error {
	clientID := info.GetID()
	Secret := info.GetSecret()
	domain := info.GetDomain()
	if clientID == "" || Secret == "" || domain == "" {
		return errors.New("clientID, secret and domain are required.")
	}

	if ok := c.checkExistence(clientID); ok {
		return errors.New("The client has already existed.")
	}

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	client := &ClientModel{
		ID:     clientID,
		Secret: Secret,
		Domain: c.parseDomain(domain),
		Data:   string(data),
	}

	return c.db.Table(c.tableName).Create(client).Error
}

// GetByDomain gets client information by the domain.
func (c *ClientStore) GetByDomain(domain string) (oauth2.ClientInfo, error) {
	if domain == "" {
		return nil, nil
	}

	var item struct{ Data string }
	err := c.db.Table(c.tableName).Select("data").Where("domain = ?", domain).Scan(&item).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return c.parseClientData(item.Data)
}

// checkExistence checks whether the client id has been created.
func (c *ClientStore) checkExistence(id string) bool {
	var count uint32
	c.db.Table(c.tableName).Where("id = ?", id).Count(&count)
	return count != 0
}

// parseDomain parses out domain for url.
func (c *ClientStore) parseDomain(url string) string {
	a := strings.Split(url, "//")
	if len(a) == 1 {
		return strings.Split(a[0], "/")[0]
	}
	return strings.Split(a[1], "/")[0]
}
