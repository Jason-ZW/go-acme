package main

import (
	"context"
	"time"

	"github.com/Jason-ZW/go-acme/acme"
	"github.com/sirupsen/logrus"
)

func main() {
	contact := []string{"mailto:zhenyang@rancher.com"}
	domains := []string{"*.api.lytall.com"}

	// Initialize ACME Client
	a, err := acme.NewACMEClient("")
	if err != nil {
		logrus.Fatalf("new acme client error, reason: %v", err)
	}

	logrus.Infof("acme client initialize success. ACME Directory Info: %v", a.Dir)

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

	logrus.Infof("acme account fetch success. ACME Account URL: %s, KID: %s", accountURL, a.Kid)

	// Create new ACME Order
	orderCtx, orderCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer orderCancel()

	oid, order, err := a.NewOrder(orderCtx, domains)
	if err != nil {
		logrus.Fatalf("new order error, reason: %v", err)
	}

	logrus.Infof("acme order initialize success. ACME Order Info: %v, OID: %s, KID: %s", order, oid, a.Kid)

	// Authorization and Challenge
	authorizationCtx, authorizationCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer authorizationCancel()

	authorization, err := a.Authorization(authorizationCtx, order)
	if err != nil {
		logrus.Fatalf("authorization error, reason: %v", err)
	}

	logrus.Infof("acme authorization success. ACME Authorization Info: %v, KID: %s", authorization, a.Kid)

	// Finalize ACME Order
	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer finalizeCancel()

	err = a.Finalize(finalizeCtx, order, oid, domains)
	if err != nil {
		logrus.Fatalf("finalize order %s error, reason: %v", oid, err)
	}

	logrus.Infof("acme finalize success. KID: %s", a.Kid)

	// Fetch ACME Account with given URL, If has valid order Account will list them
	fetchAccountCtx, fetchAccountCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer fetchAccountCancel()

	accountFetch, err := a.FetchAccount(fetchAccountCtx, accountURL)
	if err != nil {
		logrus.Fatalf("fetch account with given url %s error, reason: %v", accountURL, err)
	}

	logrus.Infof("acme account fetch success. ACME Account Info: %v, KID: %s", accountFetch, a.Kid)

	// Update ACME Account
	updateAccountCtx, updateAccountCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer updateAccountCancel()

	contact = append(contact, "mailto:30165220@rancher.com")
	accountUpdate, err := a.UpdateAccount(updateAccountCtx, contact)
	if err != nil {
		logrus.Fatalf("update account error, reason: %v", err)
	}

	logrus.Infof("acme account update success. ACME Account Info: %v, KID: %s", accountUpdate, a.Kid)

}
