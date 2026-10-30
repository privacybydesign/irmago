package usage

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-errors/errors"
)

const (
	problemBadNonce            = "urn:ietf:params:acme:error:badNonce"
	problemAccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist"
)

var (
	// ErrNotRegistered means the Portal does not know the account key: the operator has not
	// registered it, or it was deactivated.
	ErrNotRegistered = errors.New("usage reporting account key is not registered in the Yivi Portal")
)

// rejectedError is a report the Portal refused for good, other than for an unknown key.
type rejectedError struct {
	status int
	body   string
}

func (e *rejectedError) Error() string {
	return fmt.Sprintf("Yivi Portal rejected usage report (%d): %s", e.status, e.body)
}

// retryAfterError is a temporary failure for which the Portal asked to wait.
type retryAfterError struct {
	status int
	after  time.Duration
}

func (e *retryAfterError) Error() string {
	return fmt.Sprintf("Yivi Portal answered %d, retry after %s", e.status, e.after)
}

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
}

// portalClient talks to the ACME-shaped usage API of the Yivi Portal.
type portalClient struct {
	directoryURL string
	key          *ecdsa.PrivateKey
	http         *http.Client

	mu    sync.Mutex
	dir   *directory
	nonce string
}

func newPortalClient(directoryURL string, key *ecdsa.PrivateKey) *portalClient {
	return &portalClient{
		directoryURL: directoryURL,
		key:          key,
		// http.DefaultTransport honours HTTPS_PROXY and NO_PROXY.
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *portalClient) directory(ctx context.Context) (*directory, error) {
	c.mu.Lock()
	dir := c.dir
	c.mu.Unlock()
	if dir != nil {
		return dir, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Yivi Portal usage directory answered %d", res.StatusCode)
	}
	dir = &directory{}
	if err := json.NewDecoder(res.Body).Decode(dir); err != nil {
		return nil, errors.WrapPrefix(err, "failed to parse Yivi Portal usage directory", 0)
	}
	if dir.NewNonce == "" || dir.NewAccount == "" {
		return nil, errors.New("Yivi Portal usage directory is incomplete")
	}
	c.mu.Lock()
	c.dir = dir
	c.mu.Unlock()
	return dir, nil
}

func (c *portalClient) getNonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	nonce := c.nonce
	c.nonce = ""
	c.mu.Unlock()
	if nonce != "" {
		return nonce, nil
	}

	dir, err := c.directory(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	res.Body.Close()
	if nonce = res.Header.Get("Replay-Nonce"); nonce == "" {
		return "", errors.Errorf("Yivi Portal returned no nonce (%d)", res.StatusCode)
	}
	return nonce, nil
}

type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// post sends payload as a JWS to url, identifying the key by kid, or by the full public key
// when kid is empty. A rejected nonce is retried once with a fresh one.
func (c *portalClient) post(ctx context.Context, url, kid string, payload any) (*http.Response, []byte, error) {
	bts, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	for attempt := 0; ; attempt++ {
		nonce, err := c.getNonce(ctx)
		if err != nil {
			return nil, nil, err
		}
		protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
		if kid != "" {
			protected["kid"] = kid
		} else {
			protected["jwk"] = publicJWK(c.key)
		}
		body, err := signJWS(c.key, protected, bts)
		if err != nil {
			return nil, nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		res, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		resBody, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
		res.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if next := res.Header.Get("Replay-Nonce"); next != "" {
			c.mu.Lock()
			c.nonce = next
			c.mu.Unlock()
		}

		if res.StatusCode == http.StatusBadRequest && attempt == 0 && problemType(resBody) == problemBadNonce {
			continue
		}
		return res, resBody, nil
	}
}

func problemType(body []byte) string {
	p := problem{}
	_ = json.Unmarshal(body, &p)
	return p.Type
}

// lookupAccount returns the account URL (the kid) of the registered key, or ErrNotRegistered.
func (c *portalClient) lookupAccount(ctx context.Context) (string, error) {
	dir, err := c.directory(ctx)
	if err != nil {
		return "", err
	}
	res, body, err := c.post(ctx, dir.NewAccount, "", map[string]any{"onlyReturnExisting": true})
	if err != nil {
		return "", err
	}
	switch {
	case res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated:
		kid := res.Header.Get("Location")
		if kid == "" {
			return "", errors.New("Yivi Portal returned no account URL")
		}
		return kid, nil
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden ||
		problemType(body) == problemAccountDoesNotExist:
		return "", ErrNotRegistered
	default:
		return "", errors.Errorf("Yivi Portal account lookup answered %d: %s", res.StatusCode, body)
	}
}

// postReport submits a report to the account's reports endpoint.
func (c *portalClient) postReport(ctx context.Context, kid string, report *Report) error {
	res, body, err := c.post(ctx, kid+"/reports", kid, report)
	if err != nil {
		return err
	}
	switch {
	case res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated:
		return nil
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return ErrNotRegistered
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		after, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		return &retryAfterError{status: res.StatusCode, after: time.Duration(after) * time.Second}
	default:
		return &rejectedError{status: res.StatusCode, body: string(body)}
	}
}
