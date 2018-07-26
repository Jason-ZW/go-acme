package main

import (
	"context"
	"encoding/pem"
	"time"

	"golang.org/x/crypto/acme"

	goacme "github.com/Jason-ZW/go-acme/acme"
	"github.com/Jason-ZW/go-acme/config"
	"github.com/sirupsen/logrus"
)

const (
	defaultTimeout = time.Minute
)

func main() {
	domain := "ee.api.lytall.com"
	contact := []string{"mailto:zhenyang@rancher.com"}

	// generate acme client
	a, err := goacme.NewClient("")
	if err != nil {
		logrus.Fatal(err)
	}

	// register server
	registerCtx, registerCancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer registerCancel()
	err = a.Register(registerCtx, contact)
	if err != nil {
		logrus.Error(err)
	}

	// get register
	accountConfig, err := config.ReadAccountConfig()
	getReg, err := a.GetReg(registerCtx, accountConfig.Account.URI)
	if err != nil {
		logrus.Error(err)
	}
	logrus.Info(getReg)

	// request dns challenge
	authorizeCtx, authorizeCancel := context.Background(), func() {}
	defer authorizeCancel()
	authorization, err := a.Authorize(authorizeCtx, domain)
	if err != nil {
		logrus.Fatal(err)
	}

	if authorization != nil {
		if authorization.Status != acme.StatusValid {
			logrus.Fatalf("domain %s authorization failed", domain)
		}
	}

	// creating certificate request
	createCtx, createCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer createCancel()

	certURL, err := a.CreateCert(createCtx, domain)
	if err != nil {
		logrus.Fatal(err)
	}

	// fetch certificate
	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer fetchCancel()

	cert1, err := a.FetchCert(fetchCtx, certURL)
	if err != nil {
		logrus.Fatal(cert1)
	}

	var pemByte []byte
	for _, b := range cert1 {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemByte = append(pemByte, b...)
	}

	logrus.Info(string(pemByte))

	// revoke certificate
	revokeCtx, revokeCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer revokeCancel()

	err = a.RevokeCert(revokeCtx, nil, cert1[0], acme.CRLReasonSuperseded)
	if err != nil {
		logrus.Error(err)
	}

	// fetch certificate
	cert2, err := a.FetchCert(fetchCtx, certURL)
	if err != nil {
		logrus.Fatal(cert2)
	}

	var pemByte2 []byte
	for _, b := range cert2 {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemByte = append(pemByte2, b...)
	}

	logrus.Info(string(pemByte2))

}
