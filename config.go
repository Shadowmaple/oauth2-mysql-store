package store

import "time"

type BasicConfig struct {
	Addr     string
	UserName string
	Password string
	Database string
	Table    string
}

type TokenConfig struct {
	BasicConfig
	GcDisabled bool
	GcInterval time.Duration
}

type ClientConfig struct {
	BasicConfig
}

func DefaultConfig() BasicConfig {
	return BasicConfig{
		Addr:     "localhost:3306",
		UserName: "root",
		Password: "root",
		Database: "oauth2",
	}
}

func DefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		BasicConfig: DefaultConfig(),
		GcDisabled:  false,
		GcInterval:  time.Minute * 30,
	}
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		DefaultConfig(),
	}
}
