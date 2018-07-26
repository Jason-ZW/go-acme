package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
	"gopkg.in/yaml.v2"

	"github.com/sirupsen/logrus"
)

type Config struct {
	ServerPrivateKeyPath string `yaml:"serverPrivateKeyPath"`
	AccountConfigPath    string `yaml:"accountConfigPath"`
	CertSavePath         string `yaml:"certSavePath"`
}

type AccountConfig struct {
	Account *acme.Account
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

func WriteAccountConfig(a *AccountConfig) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}

	config := YAMLToConfig()
	accountConfigPath := config.AccountConfigPath
	if accountConfigPath == "" {
		return errors.New("accountConfigPath can not be empty")
	}

	if err := os.MkdirAll(accountConfigPath[0:strings.LastIndex(accountConfigPath, "/")], 0700); err != nil {
		return err
	}

	return ioutil.WriteFile(accountConfigPath, b, 0600)
}

func ReadAccountConfig() (*AccountConfig, error) {
	config := YAMLToConfig()
	accountConfigPath := config.AccountConfigPath
	if accountConfigPath == "" {
		return nil, errors.New("accountConfigPath can not be empty")
	}

	b, err := ioutil.ReadFile(accountConfigPath)
	if err != nil {
		return nil, err
	}
	accountConfig := &AccountConfig{}
	if err := json.Unmarshal(b, accountConfig); err != nil {
		return nil, err
	}
	return accountConfig, nil
}
