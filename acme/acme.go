package acme

import (
	"crypto"
	"net/http"
	"sync"

	"github.com/Jason-ZW/go-acme/config"
)

type ACME struct {
	Client *Client

	Config *config.Config
}

type Client struct {
	Directory Directory
	serverKey crypto.Signer
	Kid       string

	HTTPClient *http.Client

	nonceMux sync.Mutex
	NonceMap map[string]struct{}
}

type Directory struct {
	NewAccount string
	NewNonce   string
	RevokeCert string
	NewOrder   string
	KeyChange  string

	Meta map[string]interface{}
}

type Account struct {
	Status  string
	Contact []string
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	Status         string
	Expires        string
	Identifiers    []Identifier
	Authorizations []string
	Finalize       string
	Certificate    string
}

type Authorization struct {
	Status     string
	Expires    string
	Identifier Identifier
	Challenges []Challenge
}

type Challenge struct {
	Type             string
	URL              string
	Status           string
	Validated        string
	Token            string
	KeyAuthorization string
}
