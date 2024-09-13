package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DD_URL   string `yaml:"DD_URL"`
	DD_TOKEN string `yaml:"DD_TOKEN"`
	PORT     int    `yaml:"PORT"`
}

// LoadConfig load config.yaml
func LoadConfig() *Config {
	file, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("error reading config file: ", err)
	}

	var config Config
	if err := yaml.Unmarshal(file, &config); err != nil {
		log.Fatal("error unmarshalling config file: ", err)
	}

	return &config
}
