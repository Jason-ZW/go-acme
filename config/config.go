package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/sirupsen/logrus"
)

type Config struct {
	ServerPrivateKey string `yaml:"serverPrivateKey"`
}

func YAMLToConfig() *Config {
	data, err := ioutil.ReadFile("./config.yml")
	if err != nil {
		logrus.Fatalf("can not read config file: %v", err)
	}

	config := &Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		logrus.Fatalf("can not unmarshal to config: %v", err)
	}

	return config
}
