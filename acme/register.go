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

func (a *ACME) GetReg(ctx context.Context, uri string) (*acme.Account, error) {
	account, err := a.Client.GetReg(ctx, uri)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (a *ACME) UpdateReg(ctx context.Context, uri string, contact []string) (*acme.Account, error) {
	account, err := a.GetReg(ctx, uri)
	if err != nil {
		return nil, err
	}

	a.Account = account
	a.Account.AgreedTerms = account.CurrentTerms
	a.Account.Contact = contact

	updateAccount, err := a.Client.UpdateReg(ctx, a.Account)
	if err != nil {
		return nil, err
	}

	err = config.WriteAccountConfig(&config.AccountConfig{
		Account: updateAccount,
	})
	if err != nil {
		return nil, err
	}

	a.Account = updateAccount

	return updateAccount, nil
}
