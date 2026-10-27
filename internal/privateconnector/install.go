package privateconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const WindowsServiceName = "Contro1PrivateConnector"
const DarwinServiceName = "com.contro1.private-connector"
const DarwinServiceUser = "_contro1connector"

var enrollmentCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type Layout struct{ StateDir, BinaryPath, LogDir string }

func ProductionLayout() Layout {
	switch runtime.GOOS {
	case "windows":
		pd, pf := os.Getenv("ProgramData"), os.Getenv("ProgramFiles")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		if pf == "" {
			pf = `C:\Program Files`
		}
		return Layout{filepath.Join(pd, "Contro1", "private-connector"), filepath.Join(pf, "Contro1", "contro1-private-connector.exe"), filepath.Join(pd, "Contro1", "private-connector", "logs")}
	case "darwin":
		return Layout{"/Library/Application Support/Contro1/private-connector", "/usr/local/lib/contro1/contro1-private-connector", "/Library/Logs/Contro1/private-connector"}
	default:
		return Layout{"/var/lib/contro1-private-connector", "/usr/local/lib/contro1/contro1-private-connector", "/var/log/contro1/private-connector"}
	}
}

func CheckCapacity(root, installationID string) error {
	if !installationPattern.MatchString(installationID) {
		return errors.New("invalid installation ID")
	}
	if _, err := os.Stat(InstallationDir(root, installationID)); err == nil {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(root, "installations"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && installationPattern.MatchString(entry.Name()) {
			count++
		}
	}
	if count >= 32 {
		return errors.New("private connector installation limit exceeded")
	}
	return nil
}

type SetupInput struct {
	ServiceConfig
	EnrollmentCode string `json:"enrollment_code"`
	ProviderSecret string `json:"provider_secret,omitempty"`
}

// DecodeSetup accepts one bounded JSON object from stdin. Neither the one-use
// code nor provider credential appears in process arguments or service config.
func DecodeSetup(reader io.Reader) (SetupInput, error) {
	var input SetupInput
	raw, err := io.ReadAll(io.LimitReader(reader, 256<<10+1))
	if err != nil {
		return input, err
	}
	if len(raw) > 256<<10 {
		return input, errors.New("connector setup exceeded limit")
	}
	// The file from Contro1 marks what only this computer may fill in.
	if strings.Contains(string(raw), "REPLACE:") {
		return input, errors.New("the setup file still has REPLACE values: fill in the local API address, its IP and its credential first")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid connector setup: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return input, errors.New("connector setup contains trailing data")
	}
	if err := input.Validate(); err != nil {
		return input, err
	}
	return input, nil
}

func (input SetupInput) Validate() error {
	if !installationPattern.MatchString(input.InstallationID) {
		return errors.New("invalid installation ID")
	}
	u, err := url.Parse(input.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("cloud API must be an HTTPS origin")
	}
	if input.ProxyURL != "" {
		if _, err := ParseProxyURL(input.ProxyURL); err != nil {
			return err
		}
	}
	if input.EnrollmentCode != "" && !enrollmentCodePattern.MatchString(input.EnrollmentCode) {
		return errors.New("enrollment code must be a 43-character one-use value")
	}
	if input.Provider == nil {
		if input.ProviderSecret != "" {
			return errors.New("provider secret supplied without provider configuration")
		}
		return nil
	}
	if err := validateLocalProviderConfig(input.Provider); err != nil {
		return err
	}
	mode := input.Provider.AuthMode
	if mode == "none" && input.ProviderSecret != "" {
		return errors.New("no-credential provider cannot have a secret")
	}
	if mode != "none" && input.ProviderSecret == "" {
		return errors.New("provider credential is missing")
	}
	_, err = NewProvider(ProviderConfig{BaseURL: input.Provider.BaseURL, PinnedIP: input.Provider.PinnedIP,
		Operations: input.Provider.Operations,
		Auth:       ProviderAuth{Mode: mode, HeaderName: input.Provider.HeaderName, Username: input.Provider.Username, Secret: input.ProviderSecret}})
	return err
}

// Provision writes all local material before the service starts. The caller
// must first create an ACL-protected state directory for the service identity.
func Provision(stateDir string, input SetupInput) error {
	if err := input.Validate(); err != nil {
		return err
	}
	previous, err := ReadConfig(stateDir)
	if err == nil {
		if previous.InstallationID != input.InstallationID {
			return errors.New("this service is already bound to another installation")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if input.EnrollmentCode == "" {
			return errors.New("a fresh one-use enrollment code is required")
		}
	} else {
		return err
	}
	if err := writePrivateJSON(filepath.Join(stateDir, "config.json"), input.ServiceConfig); err != nil {
		return err
	}
	if input.EnrollmentCode != "" {
		if err := os.WriteFile(filepath.Join(stateDir, "enrollment-code"), []byte(input.EnrollmentCode), 0o600); err != nil {
			return err
		}
	}
	secretPath := filepath.Join(stateDir, "provider-secret")
	if input.ProviderSecret != "" {
		return WriteSecret(secretPath, input.ProviderSecret)
	}
	if err := os.Remove(secretPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
