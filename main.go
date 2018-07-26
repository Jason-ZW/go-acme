package main

import (
	"context"
	"time"

	"golang.org/x/crypto/acme"

	goacme "github.com/Jason-ZW/go-acme/acme"
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
	createCtx, createCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer createCancel()

	err = a.CreateCert(createCtx, domain)
	if err != nil {
		logrus.Fatal(err)
	}

	// renew certificate
}
