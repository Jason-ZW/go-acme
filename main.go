package main

import (
	"github.com/Jason-ZW/go-acme/acme"
	"github.com/sirupsen/logrus"
)

func main() {
	a, err := acme.NewACMEClient("")
	if err != nil {
		logrus.Fatalf("new acme client error, reason: %v", err)
	}

	logrus.Infof("acme initialize success. ACME Directory Info: %v", a.Dir)
}
