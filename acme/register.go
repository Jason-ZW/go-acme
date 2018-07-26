package acme

import (
	"context"

	"golang.org/x/crypto/acme"
)

func (a *ACME) Register() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	account, err := a.Client.Register(ctx, &acme.Account{Contact: []string{"mailto:zhenyang@rancher.com"}}, acme.AcceptTOS)
	if err != nil {
		return err
	}

	a.Account = account
	return nil
}
