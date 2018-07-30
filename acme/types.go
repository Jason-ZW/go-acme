package acme

import (
	"crypto"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Jason-ZW/go-acme/config"
)

type ACME struct {
	HTTPClient *http.Client

	Kid string

	// Key is the account key used to register with a CA and sign requests.
	// Key.Public() must return a *rsa.PublicKey or *ecdsa.PublicKey.
	Key crypto.Signer

	// DirectoryURL points to the CA directory endpoint.
	// If empty, LetsEncryptURL is used.
	// Mutating this value after a successful call of Client's Discover method
	// will have no effect.
	DirectoryURL string

	// RetryBackoff computes the duration after which the nth retry of a failed request
	// should occur. The value of n for the first call on failure is 1.
	// The values of r and resp are the request and response of the last failed attempt.
	// If the returned value is negative or zero, no more retries are done and an error
	// is returned to the caller of the original method.
	//
	// Requests which result in a 4xx client error are not retried,
	// except for 400 Bad Request due to "bad nonce" errors and 429 Too Many Requests.
	//
	// If RetryBackoff is nil, a truncated exponential backoff algorithm
	// with the ceiling of 10 seconds is used, where each subsequent retry n
	// is done after either ("Retry-After" + jitter) or (2^n seconds + jitter),
	// preferring the former if "Retry-After" header is found in the resp.
	// The jitter is a random value up to 1 second.
	RetryBackoff func(n int, r *http.Request, resp *http.Response) time.Duration

	dirMu sync.Mutex // guards writes to dir
	Dir   *Directory // cached result of Client's Discover method

	noncesMu sync.Mutex
	nonces   map[string]struct{} // nonces collected from previous responses

	Config *config.Config
}

type Directory struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	NewAuthz   string        `json:"newAuthz"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       DirectoryMeta `json:"meta"`
}

type DirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService"`
	Website                 string   `json:"website"`
	CaaIdentities           []string `json:"casIdentities"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type Account struct {
	Status               string
	Contact              []string
	TermsOfServiceAgreed bool
	Orders               string
}

// Error is an ACME error, defined in Problem Details for HTTP APIs doc
// http://tools.ietf.org/html/draft-ietf-appsawg-http-problem.
type Error struct {
	// StatusCode is The HTTP status code generated by the origin server.
	StatusCode int
	// ProblemType is a URI reference that identifies the problem type,
	// typically in a "urn:acme:error:xxx" form.
	ProblemType string
	// Detail is a human-readable explanation specific to this occurrence of the problem.
	Detail string
	// Header is the original server error response headers.
	// It may be nil.
	Header http.Header
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, e.ProblemType, e.Detail)
}

// wireError is a subset of fields of the Problem Details object
// as described in https://tools.ietf.org/html/rfc7807#section-3.1.
type wireError struct {
	Status int
	Type   string
	Detail string
}

func (e *wireError) error(h http.Header) *Error {
	return &Error{
		StatusCode:  e.Status,
		ProblemType: e.Type,
		Detail:      e.Detail,
		Header:      h,
	}
}
