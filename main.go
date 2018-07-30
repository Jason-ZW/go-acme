package main

import (
	"context"
	"github.com/Jason-ZW/go-acme/acme"
	"github.com/sirupsen/logrus"
	"time"
)

func main() {
	contact := []string{"mailto:zhenyang@rancher.com"}

	a, err := acme.NewACMEClient("")
	if err != nil {
		logrus.Fatalf("new acme client error, reason: %v", err)
	}

	logrus.Infof("acme initialize success. ACME Directory Info: %v", a.Dir)

	accountCtx, accountCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer accountCancel()

	account, err := a.NewAccount(accountCtx, contact)
	if err != nil {
		logrus.Fatalf("new account error, reason: %v", err)
	}

	logrus.Infof("acme account initialize success. ACME Account Info: %v, KID: %s", account, a.Kid)

	fetchAccount, err := a.FetchAccount(accountCtx)
	if err != nil {
		logrus.Fatalf("fetch account error, reason: %v", err)
	}

	logrus.Infof("acme account initialize success. ACME Account Info: %v, KID: %s", fetchAccount, a.Kid)
}
