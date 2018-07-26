package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/pkg/errors"

	"encoding/pem"
	"github.com/Jason-ZW/go-acme/config"
	"github.com/Jason-ZW/go-acme/util"
)

const (
	Expiry = 90 * 24 * time.Hour
	Bundle = true
)

func (a *ACME) CreateCert(ctx context.Context, domain string) error {
	config := config.YAMLToConfig()
	certSavePath := config.CertSavePath
	if certSavePath == "" {
		return errors.New("certSavePath can not be empty")
	}

	path := certSavePath + domain
	certKey, err := util.LoadOrGenerateKey(path + "/private.key")
	if err != nil {
		return err
	}
	certRequest := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, certKey)
	if err != nil {
		return err
	}

	der, _, err := a.Client.CreateCert(ctx, csr, Expiry, Bundle)
	if err != nil {
		return err
	}

	var pemByte []byte
	for _, b := range der {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemByte = append(pemByte, b...)
	}

	err = util.GeneratePEM(path+"/cert.crt", pemByte)
	return err
}

func(a *ACME) FetchCert(ctx context.Context, uri string) ([][]byte, error) {
	return a.Client.FetchCert(ctx, uri, Bundle)
}
