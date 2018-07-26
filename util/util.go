package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"

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

func LoadOrGenerateKey(file string) (crypto.Signer, error) {
	key, err := LoadKey(file)
	if err == nil {
		return key, err
	} else {
		csdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logrus.Error(err)
			return nil, err
		}
		return csdsaKey, GenerateKey(file, csdsaKey)
	}
}

func LoadKey(file string) (crypto.Signer, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		logrus.Infof("open %s: no such file or directory, will re-generate key file", file)
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		logrus.Errorf("failed to decode pem file: no key found")
		return nil, errors.Errorf("unsupported type: %s", block.Type)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		logrus.Errorf("unsupported type: %s", block.Type)
		return nil, errors.Errorf("unsupported type: %s", block.Type)
	}
}

func GenerateKey(path string, k *ecdsa.PrivateKey) error {
	os.MkdirAll(path[0:strings.LastIndex(path, "/")], 0700)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	bytes, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	b := &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}
	if err := pem.Encode(f, b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func GeneratePEM(path string, data []byte) error {
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return err
	}
	return nil
}
