package acme

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"

	"github.com/Jason-ZW/go-acme/config"
	"github.com/Jason-ZW/go-acme/util"
)

const (
	letsencrypt        = "https://acme-v01.api.letsencrypt.org/directory"
	letsencryptStaging = "https://acme-staging.api.letsencrypt.org/directory"

	challengeDNS = "dns-01"
)

type ACME struct {
	Client  *acme.Client
	Account *acme.Account
	config  config.Config
}

func NewClient(directoryURL string) (*ACME, error) {
	if directoryURL == "" {
		directoryURL = letsencrypt
	}

	config := config.YAMLToConfig()

	privateKeyPath := config.ServerPrivateKeyPath
	if privateKeyPath == "" {
		return nil, errors.New("serverPrivateKeyPath can not be empty")
	}

	a := &ACME{
		Client: &acme.Client{
			Key:          util.LoadServerPrivateKey(privateKeyPath),
			DirectoryURL: directoryURL,
		},
	}

	return a, nil
}
