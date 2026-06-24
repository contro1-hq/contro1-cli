// Package config manages the contro1 CLI configuration file (~/.contro1/config.yaml).
//
// It supports multiple named profiles (gcloud-style configurations), each with its
// own API endpoint and last-known account. Token values are NOT stored here - they
// live in the OS keychain (see package keychain).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// Production defaults so a freshly installed CLI works with no configuration.
	// Point at a local stack with `contro1 config set api-url/web-url` for dev.
	DefaultAPIURL = "https://api.contro1.com"
	DefaultWebURL = "https://contro1.com"
)

// Profile is a single named configuration.
type Profile struct {
	APIURL        string   `yaml:"api_url"`
	WebURL        string   `yaml:"web_url"`
	OperatorEmail string   `yaml:"operator_email,omitempty"`
	OrgName       string   `yaml:"org_name,omitempty"`
	TokenID       string   `yaml:"token_id,omitempty"`
	Scopes        []string `yaml:"scopes,omitempty"`
	OutputFormat  string   `yaml:"output_format,omitempty"`
}

// Config is the on-disk root document.
type Config struct {
	CurrentProfile string              `yaml:"current_profile"`
	Profiles       map[string]*Profile `yaml:"profiles"`
}

// Dir returns the configuration directory, creating it if needed.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".contro1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func defaultProfile() *Profile {
	return &Profile{APIURL: DefaultAPIURL, WebURL: DefaultWebURL, OutputFormat: "table"}
}

// Load reads the config file, seeding sensible defaults when it does not exist.
func Load() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &Config{
			CurrentProfile: "default",
			Profiles:       map[string]*Profile{"default": defaultProfile()},
		}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	if c.CurrentProfile == "" {
		c.CurrentProfile = "default"
	}
	if _, ok := c.Profiles[c.CurrentProfile]; !ok {
		c.Profiles[c.CurrentProfile] = defaultProfile()
	}
	return &c, nil
}

// Save writes the config file with restrictive permissions.
func (c *Config) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// Profile returns the named profile, or the current one when name is empty.
// A missing profile is created on the fly with defaults.
func (c *Config) Profile(name string) *Profile {
	if name == "" {
		name = c.CurrentProfile
	}
	if name == "" {
		name = "default"
	}
	pr, ok := c.Profiles[name]
	if !ok {
		pr = defaultProfile()
		c.Profiles[name] = pr
	}
	if pr.APIURL == "" {
		pr.APIURL = DefaultAPIURL
	}
	if pr.WebURL == "" {
		pr.WebURL = DefaultWebURL
	}
	return pr
}

// ActiveName resolves the effective profile name given an optional override.
func (c *Config) ActiveName(override string) string {
	if override != "" {
		return override
	}
	if c.CurrentProfile != "" {
		return c.CurrentProfile
	}
	return "default"
}
