package main

import (
	"github.com/Jason-ZW/go-acme/acme"
	"github.com/sirupsen/logrus"
)

func main() {
	a, err := acme.NewClient("")
	if err != nil {
		logrus.Fatal(err)
	}

	err = a.Register()
	if err != nil {
		logrus.Error(err)
	}

}
