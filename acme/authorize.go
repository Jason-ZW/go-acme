package acme

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

func (a *ACME) Authorize(ctx context.Context, domain string) (*acme.Authorization, error) {
	z, err := a.Client.Authorize(ctx, domain)
	if err != nil {
		return nil, err
	}

	if z.Status == acme.StatusValid {
		return z, nil
	}

	var challenge *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == challengeDNS {
			challenge = c
			break
		}
	}

	if challenge == nil {
		return nil, errors.New("no supported dns challenge found")
	}

	token, err := a.Client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return nil, err
	}

	fmt.Printf(`Please deploy a DNS TXT record under the name
_acme-challenge.%s with the following value:

%s

Before continuing, verify the record is deployed.
Press Enter to Continue`, domain, token)
	var enter string
	fmt.Scanln(&enter)

	if _, err := a.Client.Accept(ctx, challenge); err != nil {
		return nil, err
	}

	authorization, err := a.Client.WaitAuthorization(ctx, z.URI)
	return authorization, err
}

func (a *ACME) RevokeAuthorize(ctx context.Context, uri string) error {
	return a.Client.RevokeAuthorization(ctx, uri)
}
