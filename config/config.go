package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DD_URL   string `yaml:"DD_URL"`
	DD_TOKEN string `yaml:"DD_TOKEN"`
	PORT     int    `yaml:"PORT"`
}

// LoadConfig load config.yaml
func LoadConfig(fileName string) (*Config, error) {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("error unmarshalling config file: %w", err)
	}

	return &cfg, nil
}
