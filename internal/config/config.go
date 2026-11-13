// Package config loads the service's deployment settings without logging secrets.
package config

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

type Config struct {
	Port    int
	JWKSURL string
	DataDir string
}

func Load(lookup func(string) (string, bool)) (Config, error) {
	cfg := Config{Port: 8080, JWKSURL: "http://auth:8080/.well-known/jwks.json"}
	if raw, ok := lookup("PORT"); ok {
		port, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || port < 1 || port > 65535 {
			return Config{}, errors.New("invalid PORT")
		}
		cfg.Port = port
	}
	if raw, _ := lookup("BANWORDS_JWKS_URL"); raw != "" {
		cfg.JWKSURL = raw
	}
	u, err := url.Parse(cfg.JWKSURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return Config{}, errors.New("invalid BANWORDS_JWKS_URL")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value > 65535 {
			return Config{}, errors.New("invalid BANWORDS_JWKS_URL")
		}
	}
	cfg.DataDir, _ = lookup("BANWORDS_DATA_DIR")
	return cfg, nil
}
