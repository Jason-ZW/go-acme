package main

import (
	"context"
	"github.com/Jason-ZW/go-acme/acme"
	"github.com/sirupsen/logrus"
	"time"
)

func main() {
	contact := []string{"mailto:zhenyang@rancher.com"}

	// Initialize ACME Client
	a, err := acme.NewACMEClient("")
	if err != nil {
		logrus.Fatalf("new acme client error, reason: %v", err)
	}

	logrus.Infof("acme initialize success. ACME Directory Info: %v", a.Dir)

	// Create new ACME Account
	accountCtx, accountCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer accountCancel()

	account, err := a.NewAccount(accountCtx, contact)
	if err != nil {
		logrus.Fatalf("new account error, reason: %v", err)
	}

	logrus.Infof("acme account initialize success. ACME Account Info: %v, KID: %s", account, a.Kid)

	// Fetch ACME Account URL with given Key
	accountURL, err := a.FetchAccountURL(accountCtx)
	if err != nil {
		logrus.Fatalf("fetch account error, reason: %v", err)
	}

	logrus.Infof("acme account initialize success. ACME Account URL: %s, KID: %s", accountURL, a.Kid)

	// Update ACME Account
	contact = append(contact, "mailto:30165220@rancher.com")
	accountUpdate, err := a.UpdateAccount(accountCtx, contact)
	if err != nil {
		logrus.Fatalf("update account error, reason: %v", err)
	}

	logrus.Infof("acme account initialize success. ACME Account Info: %v, KID: %s", accountUpdate, a.Kid)

}
