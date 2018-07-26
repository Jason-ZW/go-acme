package acme

import (
	"context"

	"golang.org/x/crypto/acme"

	"github.com/Jason-ZW/go-acme/config"
)

func (a *ACME) Register(ctx context.Context, contact []string) error {
	account, err := a.Client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err != nil {
		return err
	}

	a.Account = account

	return config.WriteAccountConfig(&config.AccountConfig{
		Account: account,
	})
}
