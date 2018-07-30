package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/Jason-ZW/go-acme/config"
	"github.com/Jason-ZW/go-acme/util"
	"github.com/sirupsen/logrus"
)

const (
	letsencrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	letsencryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	challengeDNS01 = "dns-01"

	// Max number of collected nonces kept in memory.
	// Expect usual peak of 1 or 2.
	maxNonces      = 100
	defaultTimeout = 1 * time.Minute
)

// timeNow is useful for testing for fixed current time.
var timeNow = time.Now

func NewACMEClient(directoryURL string) (*ACME, error) {
	if directoryURL == "" {
		directoryURL = letsencryptStaging
	}

	config := config.YAMLToConfig()

	privateKeyPath := config.ServerPrivateKeyPath
	if privateKeyPath == "" {
		return nil, errors.New("server private key path can not be empty")
	}

	key, err := util.LoadServerPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	a := &ACME{
		Key:          key,
		DirectoryURL: directoryURL,
		HTTPClient:   http.DefaultClient,
	}

	// invoke a.Discover() function in order to add dir information.
	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer discoverCancel()

	_, err = a.Discover(discoverCtx)
	if err != nil {
		return a, err
	}

	return a, nil
}

func (c *ACME) Discover(ctx context.Context) (Directory, error) {
	c.dirMu.Lock()
	defer c.dirMu.Unlock()
	if c.Dir != nil {
		return *c.Dir, nil
	}

	res, err := c.get(ctx, c.DirectoryURL, wantStatus(http.StatusOK))
	if err != nil {
		return Directory{}, err
	}
	defer res.Body.Close()
	c.addNonce(res.Header)

	dir := &Directory{}
	if err := json.NewDecoder(res.Body).Decode(&dir); err != nil {
		return *dir, errors.Errorf("acme: invalid response: %v", err)
	}

	c.Dir = dir

	return *dir, nil
}

func (c *ACME) NewAccount(ctx context.Context, contact []string) (*Account, error) {
	req := struct {
		Contact              []string `json:"contact,omitempty"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	}{
		Contact:              contact,
		TermsOfServiceAgreed: true,
	}

	res, err := c.post(ctx, "", c.Key, c.Dir.NewAccount, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	account := &Account{}

	if err := util.DecodeResponse(res, &account); err != nil {
		return account, err
	}

	location := res.Header.Get("Location")
	if location == "" {
		return account, errors.New("acme: location can not be empty")
	}

	c.Kid = location

	return account, nil
}

func (c *ACME) FetchAccountURL(ctx context.Context) (string, error) {
	req := struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}{
		OnlyReturnExisting: true,
	}

	res, err := c.post(ctx, "", c.Key, c.Dir.NewAccount, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	account := &Account{}

	if err := util.DecodeResponse(res, &account); err != nil {
		return "", errors.Errorf("acme: invalid response: %v", err)
	}

	location := res.Header.Get("Location")
	if location == "" {
		return "", errors.New("acme: location can not be empty")
	}

	c.Kid = location

	return location, nil
}

func (c *ACME) FetchAccount(ctx context.Context, url string) (*Account, error) {
	if url == "" {
		url = c.Kid
	}
	req := struct{}{}

	res, err := c.post(ctx, c.Kid, c.Key, url, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return &Account{}, err
	}
	defer res.Body.Close()

	account := &Account{}
	if err := json.NewDecoder(res.Body).Decode(&account); err != nil {
		return account, errors.Errorf("acme: invalid response: %v", err)
	}

	return account, nil
}

func (c *ACME) UpdateAccount(ctx context.Context, contact []string) (*Account, error) {
	req := struct {
		Contact              []string `json:"contact,omitempty"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	}{
		Contact:              contact,
		TermsOfServiceAgreed: true,
	}

	res, err := c.post(ctx, c.Kid, c.Key, c.Kid, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	account := &Account{}

	if err := util.DecodeResponse(res, &account); err != nil {
		return account, errors.Errorf("acme: invalid response: %v", err)
	}

	return account, nil
}

func (c *ACME) NewOrder(ctx context.Context, domains []string) (string, *Order, error) {
	// check account already exist
	_, err := c.FetchAccountURL(ctx)
	if err != nil {
		return "", nil, err
	}

	// apply order: add domain identifier which need by authorization
	var identifiers []Identifier
	for _, domain := range domains {
		identifiers = append(identifiers, Identifier{Type: "dns", Value: domain})
	}

	req := struct {
		Identifiers []Identifier `json:"identifiers"`
	}{
		Identifiers: identifiers,
	}

	res, err := c.post(ctx, c.Kid, c.Key, c.Dir.NewOrder, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return "", nil, err
	}
	defer res.Body.Close()

	location := res.Header.Get("Location")

	order := &Order{}

	if err := util.DecodeResponse(res, &order); err != nil {
		return location, order, errors.Errorf("acme: invalid response: %v", err)
	}

	return location, order, nil
}

func (c *ACME) FetchOrder(ctx context.Context, oid string) (*Order, error) {
	res, err := c.get(ctx, oid, wantStatus(http.StatusOK))
	if err != nil {
		return &Order{}, err
	}
	defer res.Body.Close()
	c.addNonce(res.Header)

	order := &Order{}
	if err := json.NewDecoder(res.Body).Decode(&order); err != nil {
		return order, errors.Errorf("acme: invalid response: %v", err)
	}

	return order, nil
}

func (c *ACME) Finalize(ctx context.Context, order *Order, oid string, domains []string) error {
	config := config.YAMLToConfig()
	certSavePath := config.CertSavePath
	if certSavePath == "" {
		return errors.New("cert save path can not be empty")
	}

	path := certSavePath + domains[0]
	certKey, err := util.LoadOrGenerateKey(path + "/private.key")
	if err != nil {
		return err
	}
	certRequest := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, certKey)
	if err != nil {
		return err
	}

	req := struct {
		CSR string `json:"csr"`
	}{
		CSR: base64.RawURLEncoding.EncodeToString(csr),
	}

	_, err = c.post(ctx, c.Kid, c.Key, order.Finalize, req, wantStatus(
		http.StatusOK,       // updates and deletes
		http.StatusCreated,  // new account creation
		http.StatusAccepted, // Let's Encrypt divergent implementation
	))
	if err != nil {
		return err
	}

	// fetch order with retry
	orderFetch, err := c.FetchOrder(ctx, oid)
	if err != nil {
		return err
	}

	if orderFetch.Status != StatusValid {
		return errors.Errorf("acme: finalize order error, order status should be %s but %s", StatusValid, order.Status)
	}

	// save to /etc/go-acme/<domain>/

	return util.GeneratePEM(path+"/cert.crt", orderFetch.Certificate)
}

func (c *ACME) Authorization(ctx context.Context, order *Order) (*Authorization, error) {
	if order.Status != StatusPending {
		return nil, errors.Errorf("acme: order status '%s' is invalid, should be pending", order.Status)
	}

	if len(order.Authorizations) == 0 {
		return nil, errors.New("acme: order authorizations is invalid, should not be 0")
	}

	for _, authz := range order.Authorizations {
		authorization, err := c.FetchAuthorization(ctx, authz)
		if err != nil {
			return nil, err
		}

		if authorization.Status == "valid" {
			return authorization, nil
		}

		if len(authorization.Challenges) == 0 {
			return authorization, errors.New("acme: authorization challenges is invalid, should not be 0")
		}

		var challenge *Challenge
		for _, c := range authorization.Challenges {
			if c.Type == challengeDNS01 {
				challenge = &c
				break
			}
		}

		if challenge == nil {
			return authorization, errors.New("acme: authorization challenges should contain dns-01, because only dns-01 is supported by go-acme")
		}

		if challenge.Status == "valid" {
			return authorization, nil
		}

		// challenge DNS with dns-01
		isSuccess := c.ChallengeDNS01(ctx, authorization, challenge)
		if isSuccess {
			authorization, err := c.WaitAuthorization(ctx, authz)
			return authorization, err
		}

		return authorization, errors.New("acme: ")

	}

	return nil, nil
}

func (c *ACME) FetchAuthorization(ctx context.Context, url string) (*Authorization, error) {
	res, err := c.get(ctx, url, wantStatus(http.StatusOK))
	if err != nil {
		return &Authorization{}, err
	}
	defer res.Body.Close()
	c.addNonce(res.Header)

	auth := &Authorization{}
	if err := json.NewDecoder(res.Body).Decode(&auth); err != nil {
		return auth, errors.Errorf("acme: invalid response: %v", err)
	}
	return auth, nil
}

func (c *ACME) ChallengeDNS01(ctx context.Context, authorization *Authorization, challenge *Challenge) bool {
	domain := authorization.Identifier.Value
	token, err := c.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		logrus.Errorf("acme: fetch dns-01 challenge record error, reason: %v", err)
		return false
	}

	fmt.Printf(`Please deploy a DNS TXT record under the name
_acme-challenge.%s with the following value:
%s
Before continuing, verify the record is deployed.
Press Enter to Continue`, domain, token)
	var enter string
	fmt.Scanln(&enter)

	challengeAccepted, err := c.Accept(ctx, challenge)

	if err != nil {
		logrus.Errorf("acme: accepts one of its challenges %s error, reason: %v", challenge.URL, err)
		return false
	}

	logrus.Infof("11111111 %s", challengeAccepted.Status)

	return true
}

// popNonce returns a nonce value previously stored with c.addNonce
// or fetches a fresh one from the given URL.
func (c *ACME) popNonce(ctx context.Context, url string) (string, error) {
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	if len(c.nonces) == 0 {
		return c.fetchNonce(ctx, url)
	}
	var nonce string
	for nonce = range c.nonces {
		delete(c.nonces, nonce)
		break
	}
	return nonce, nil
}

// clearNonces clears any stored nonces
func (c *ACME) clearNonces() {
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	c.nonces = make(map[string]struct{})
}

// addNonce stores a nonce value found in h (if any) for future use.
func (c *ACME) addNonce(h http.Header) {
	v := nonceFromHeader(h)
	if v == "" {
		return
	}
	c.noncesMu.Lock()
	defer c.noncesMu.Unlock()
	if len(c.nonces) >= maxNonces {
		return
	}
	if c.nonces == nil {
		c.nonces = make(map[string]struct{})
	}
	c.nonces[v] = struct{}{}
}

func (c *ACME) fetchNonce(ctx context.Context, url string) (string, error) {
	r, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.doNoRetry(ctx, r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	nonce := nonceFromHeader(resp.Header)
	if nonce == "" {
		if resp.StatusCode > 299 {
			return "", responseError(resp)
		}
		return "", errors.New("acme: nonce not found")
	}
	return nonce, nil
}

func nonceFromHeader(h http.Header) string {
	return h.Get("Replay-Nonce")
}

// DNS01ChallengeRecord returns a DNS record value for a dns-01 challenge response.
// A TXT record containing the returned value must be provisioned under
// "_acme-challenge" name of the domain being validated.
//
// The token argument is a Challenge.Token value.
func (c *ACME) DNS01ChallengeRecord(token string) (string, error) {
	ka, err := keyAuth(c.Key.Public(), token)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(ka))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// keyAuth generates a key authorization string for a given token.
func keyAuth(pub crypto.PublicKey, token string) (string, error) {
	thum, err := JWKThumbprint(pub)
	if err != nil {
		return "", err
	}

	ka := token + "." + thum

	return ka, nil
}

// Accept informs the server that the client accepts one of its challenges
// previously obtained with c.Authorize.
//
// The server will then perform the validation asynchronously.
func (c *ACME) Accept(ctx context.Context, chal *Challenge) (*Challenge, error) {
	auth, err := keyAuth(c.Key.Public(), chal.Token)
	if err != nil {
		return nil, err
	}

	req := struct {
		KeyAuthorization string `json:"keyAuthorization"`
		Type             string `json:"type"`
	}{
		KeyAuthorization: auth,
		Type:             chal.Type,
	}
	res, err := c.post(ctx, c.Kid, c.Key, chal.URL, req, wantStatus(
		http.StatusOK,       // according to the spec
		http.StatusAccepted, // Let's Encrypt: see https://goo.gl/WsJ7VT (acme-divergences.md)
	))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var v wireChallenge
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid response: %v", err)
	}
	return v.challenge(), nil
}

// WaitAuthorization polls an authorization at the given URL
// until it is in one of the final states, StatusValid or StatusInvalid,
// the ACME CA responded with a 4xx error code, or the context is done.
//
// It returns a non-nil Authorization only if its Status is StatusValid.
// In all other cases WaitAuthorization returns an error.
// If the Status is StatusInvalid, the returned error is of type *AuthorizationError.
func (c *ACME) WaitAuthorization(ctx context.Context, url string) (*Authorization, error) {
	for {
		res, err := c.get(ctx, url, wantStatus(http.StatusOK, http.StatusAccepted))
		if err != nil {
			return nil, err
		}

		raw := &Authorization{}
		err = util.DecodeResponse(res, raw)
		res.Body.Close()
		switch {
		case err != nil:
			// Skip and retry.
		case raw.Status == StatusValid:
			return raw, nil
		case raw.Status == StatusInvalid:
			return nil, errors.Errorf("acme: wait authorization %s status to be %s failed, status is: %s", url, StatusValid, raw.Status)
		}

		// Exponential backoff is implemented in c.get above.
		// This is just to prevent continuously hitting the CA
		// while waiting for a final authorization status.
		d := retryAfter(res.Header.Get("Retry-After"))
		if d == 0 {
			// Given that the fastest challenges TLS-SNI and HTTP-01
			// require a CA to make at least 1 network round trip
			// and most likely persist a challenge state,
			// this default delay seems reasonable.
			d = time.Second
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
			// Retry.
		}
	}
}
