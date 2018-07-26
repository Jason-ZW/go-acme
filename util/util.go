package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/url"

	"github.com/sirupsen/logrus"
)

func LoadServerPrivateKey(file string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		logrus.Fatalf("can not read server privateKey file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		logrus.Fatalf("failed to decode pem file: no key found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logrus.Fatalf("failed to parse privateKey: %v:", err)
	}

	return privateKey
}

func PathToURL(baseURL *url.URL, path string) string {
	var u url.URL
	u = *baseURL
	u.Path = path
	return u.String()
}
