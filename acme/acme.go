package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/Jason-ZW/go-acme/config"
	"github.com/Jason-ZW/go-acme/util"
)

const (
	letsencrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	letsencryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	challengeDNS = "dns-01"

	// Max number of collected nonces kept in memory.
	// Expect usual peak of 1 or 2.
	maxNonces      = 100
	defaultTimeout = 1 * time.Minute
)

// timeNow is useful for testing for fixed current time.
var timeNow = time.Now

func NewACMEClient(directoryURL string) (*ACME, error) {
	if directoryURL == "" {
		directoryURL = letsencrypt
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
		return Directory{}, err
	}

	c.Dir = dir

	return *dir, nil
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
