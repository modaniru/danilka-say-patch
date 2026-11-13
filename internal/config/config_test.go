package config

import "testing"

func environment(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func TestLoad(t *testing.T) {
	cfg, err := Load(environment(nil))
	if err != nil || cfg.Port != 8080 || cfg.JWKSURL != "http://auth:8080/.well-known/jwks.json" || cfg.DataDir != "" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = Load(environment(map[string]string{"PORT": " 9876 ", "BANWORDS_JWKS_URL": "https://auth.test/keys", "BANWORDS_DATA_DIR": "/data"}))
	if err != nil || cfg.Port != 9876 || cfg.JWKSURL != "https://auth.test/keys" || cfg.DataDir != "/data" {
		t.Fatalf("explicit: %+v %v", cfg, err)
	}
	cfg, err = Load(environment(map[string]string{"BANWORDS_JWKS_URL": ""}))
	if err != nil || cfg.JWKSURL != "http://auth:8080/.well-known/jwks.json" {
		t.Fatalf("empty URL fallback: %+v %v", cfg, err)
	}
}
func TestRejectInvalidConfig(t *testing.T) {
	for _, port := range []string{"", "0", "65536", "-1", "x", "3.5"} {
		t.Run("port"+port, func(t *testing.T) {
			if _, err := Load(environment(map[string]string{"PORT": port})); err == nil {
				t.Fatal("invalid port accepted")
			}
		})
	}
	for _, url := range []string{"file:///tmp/keys", "ftp://auth/keys", "http://user:pass@auth/keys", "http://user@auth/keys", "not-url", "http://", "http://%xx", "http://auth:65536/keys", "http://auth:999999999999999999999999/keys"} {
		t.Run(url, func(t *testing.T) {
			if _, err := Load(environment(map[string]string{"BANWORDS_JWKS_URL": url})); err == nil {
				t.Fatal("invalid URL accepted")
			}
		})
	}
}
