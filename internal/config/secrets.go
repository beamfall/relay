package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func SecretFromEnvOrFile(envValue, filePath string) ([]byte, error) {
	if envValue != "" {
		if secret := strings.TrimSpace(envValue); secret != "" {
			return []byte(secret), nil
		}
	}
	if filePath == "" {
		return nil, errors.New("secret env value or file path is required")
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat secret file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file %s must not be readable by group or others", filePath)
	}
	contents, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	secret := strings.TrimSpace(string(contents))
	if secret == "" {
		return nil, errors.New("secret is empty")
	}
	return []byte(secret), nil
}

// OptionalSecretFromEnvOrFile is SecretFromEnvOrFile for secrets that are
// allowed to be absent: when neither the env value nor the file path is set it
// returns nil with no error instead of failing. Used for the admin /metrics
// bearer credential, which is only required for a non-loopback admin bind
// (relay.Start fails closed there).
func OptionalSecretFromEnvOrFile(envValue, filePath string) ([]byte, error) {
	if envValue == "" && filePath == "" {
		return nil, nil
	}
	return SecretFromEnvOrFile(envValue, filePath)
}

func EnvOrDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
