package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"

	"github.com/Jason-ZW/go-acme/config"
	"github.com/Jason-ZW/go-acme/util"
	"github.com/sirupsen/logrus"
)

func (a *ACME) CreateCert(ctx context.Context, domain string) (string, error) {
	config := config.YAMLToConfig()
	certSavePath := config.CertSavePath
	if certSavePath == "" {
		return "", errors.New("certSavePath can not be empty")
	}

	path := certSavePath + domain
	certKey, err := util.LoadOrGenerateKey(path + "/private.key")
	if err != nil {
		return "", err
	}
	certRequest := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, certKey)
	if err != nil {
		return "", err
	}

	der, certURL, err := a.Client.CreateCert(ctx, csr, util.Expiry, util.Bundle)
	if err != nil {
		return "", err
	}

	logrus.Infof("Let's encrypt domain %s's cert permanent url is %s", domain, certURL)

	var pemByte []byte
	for _, b := range der {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemByte = append(pemByte, b...)
	}

	err = util.GeneratePEM(path+"/cert.crt", pemByte)
	return certURL, err
}

func (a *ACME) FetchCert(ctx context.Context, uri string) ([][]byte, error) {
	return a.Client.FetchCert(ctx, uri, util.Bundle)
}

func (a *ACME) RevokeCert(ctx context.Context, key crypto.Signer, cert []byte, reason acme.CRLReasonCode) error {
	return a.Client.RevokeCert(ctx, key, cert, reason)
}

func (a *ACME) RenewCert(ctx context.Context, b []byte, domain string) (string, error) {
	certs, err := util.ParsePEMBundle(b)
	if err != nil {
		logrus.Error(err)
	}

	needsUpdate := util.NeedsUpdate(certs[0])
	if needsUpdate {
		certURL, err := a.CreateCert(ctx, domain)
		return certURL, err
	}
	valid := int(certs[0].NotAfter.Sub(time.Now().UTC()).Hours())
	logrus.Infof("domain %s certificate is valid, %d hours left, no need renew.", domain, valid)
	return "", nil
}
