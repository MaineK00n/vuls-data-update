package github

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

const baseURL = "https://api.github.com"

// Scopes required to operate on the GitHub Container Registry.
// ref. https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
const (
	ScopeReadPackages   = "read:packages"
	ScopeWritePackages  = "write:packages"
	ScopeDeletePackages = "delete:packages"
)

// impliedScopes maps a granted scope to the scopes it grants implicitly.
var impliedScopes = map[string][]string{
	ScopeWritePackages: {ScopeReadPackages},
}

type options struct {
	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
}

// retryPolicy is how Do retries a request that failed for a reason that
// passes.
type retryPolicy struct {
	// max is the number of retries after the first attempt.
	max int
	// waitMin and waitMax bound the exponential backoff between the retries of
	// a connection error or a 5xx response.
	waitMin, waitMax time.Duration
	// rateLimitWait is the first wait for a rate limit that does not say how
	// long to wait, for which GitHub asks for at least a minute, and for one
	// that persists for a wait that grows with each retry. It doubles with each
	// retry, up to askedWaitMax, and a random part of up to rateLimitWait on
	// top keeps clients that were refused in the same second from retrying in
	// the same second again.
	rateLimitWait time.Duration
	// askedWaitMax is the longest wait GitHub may ask for, by a rate limit or
	// by the Retry-After of a 503. A request asked to wait longer, as one is
	// when the primary rate limit resets most of an hour later, fails at once
	// rather than holding the caller up that long.
	askedWaitMax time.Duration
}

// policy is a variable only so that the tests of this package can shorten the
// waits, through export_test.go.
var policy = retryPolicy{
	max:           4,
	waitMin:       1 * time.Second,
	waitMax:       30 * time.Second,
	rateLimitWait: 1 * time.Minute,
	askedWaitMax:  5 * time.Minute,
}

// Do sends the request with client, or with [http.DefaultClient] when it is
// nil, and hands the response to fn. Tests pass the client of an
// httptest.NewTestServer, whose in-memory network routes every request to the
// test server regardless of host, so the caller keeps using the production API
// URL.
//
// A request that fails for a reason that passes is retried before fn sees it:
// a connection error and a 5xx response with exponential backoff, and a rate
// limit and a 503 that says how long to wait after the wait GitHub asks for, as
// long as it is no longer than policy.askedWaitMax. A rate limit that does not
// say is retried after a wait that grows with each retry. A DELETE is retried
// as well, as a version id is never reused, but a retry whose first attempt
// went through is answered 404, which the caller has to take for done. A
// caller whose request is only to be sent while something holds, such as a
// DELETE of a version that is to be untagged, checks it again before each
// retry with WithBeforeRetry, as the retries can wait for minutes.
//
// Once the retries run out, fn sees the last response, and the error it returns
// for a status it does not expect carries what GitHub said about it. A rate
// limit is the exception: Do fails with ErrRateLimited and what GitHub said,
// such as which rate limit was hit, without handing the response to fn, so
// that no fn takes it for a 403 that refuses the token.
func Do(client *http.Client, method, apiurl, token string, fn func(resp *http.Response) error, opts ...DoOption) error {
	if client == nil {
		client = http.DefaultClient
	}

	var o doOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	u, err := url.Parse(apiurl)
	if err != nil {
		return errors.Wrap(err, "parse url")
	}

	header := make(http.Header)
	header.Set("Accept", "application/vnd.github+json")
	header.Set("X-GitHub-Api-Version", "2022-11-28")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	req, err := retryablehttp.NewRequest(method, u.String(), nil)
	if err != nil {
		return errors.Wrap(err, "create request")
	}
	req.Header = header

	r := &retrier{method: method, url: u.String()}
	c := &retryablehttp.Client{
		HTTPClient:   client,
		RetryWaitMin: policy.waitMin,
		RetryWaitMax: policy.waitMax,
		RetryMax:     policy.max,
		CheckRetry:   r.checkRetry,
		Backoff:      r.backoff,
		// Hand the last response to fn, which reports a status it does not
		// expect in the words of the caller, rather than closing it.
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}
	if o.beforeRetry != nil {
		// PrepareRetry runs after the wait, right before the retry is sent.
		c.PrepareRetry = func(*http.Request) error {
			if err := o.beforeRetry(); err != nil {
				return errors.Wrap(err, "check before the retry")
			}
			return nil
		}
	}

	resp, err := c.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return errors.Wrapf(err, "%s: %s", method, u.String())
	}
	defer resp.Body.Close()

	if r.rateLimited {
		return errors.Wrapf(ErrRateLimited, "%s: %s. %s", method, u.String(), describe(resp))
	}

	if err := fn(resp); err != nil {
		if resp.StatusCode >= http.StatusBadRequest {
			return errors.Wrapf(err, "process response. %s", describe(resp))
		}
		return errors.Wrap(err, "process response")
	}

	return nil
}

// ErrRateLimited is what the error of Do is, by errors.Is, for a request that
// GitHub refused for a rate limit and that the retries did not get past, as
// they ran out or as GitHub asked for a longer wait than policy.askedWaitMax.
// Every request is refused the same way until the limit lifts, and GitHub warns
// that one that keeps making requests while rate limited may be banned, so a
// caller with more requests to make stops there.
//
// ref. https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#handle-rate-limit-errors-appropriately
var ErrRateLimited = errors.New("rate limited")

// DoOption is an option of Do.
type DoOption interface {
	apply(*doOptions)
}

type doOptions struct {
	beforeRetry func() error
}

// WithBeforeRetry has Do call check before each retry of the request, right
// before it is sent. A check that fails ends the retries, and Do returns its
// error without sending the request again.
func WithBeforeRetry(check func() error) DoOption {
	return beforeRetryOption(check)
}

type beforeRetryOption func() error

func (f beforeRetryOption) apply(o *doOptions) {
	o.beforeRetry = f
}

// retrier decides on the retries of one request. retryablehttp drains the body
// of a response it retries before it asks for the wait, so checkRetry, which
// still has the body, works the wait GitHub asks for out and leaves it to
// backoff.
type retrier struct {
	method string
	url    string

	// reason is why the last attempt failed, for the log.
	reason string
	// asked is what the last response asked for, and ok tells that it asked.
	asked ask
	ok    bool
	// rateLimited tells that the last response was a rate limit.
	rateLimited bool
}

// checkRetry retries what retryablehttp.DefaultRetryPolicy does, which is a
// connection error, a 5xx response and 429, and a 403 that is a rate limit.
// GitHub answers a rate limit with 403 as often as with 429.
//
// ref. https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#handle-rate-limit-errors-appropriately
func (r *retrier) checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	r.ok, r.rateLimited = false, false
	switch {
	case err != nil:
		r.reason = err.Error()
	case resp != nil:
		r.reason = resp.Status

		a, ok, err := askedWait(resp)
		if err != nil {
			return false, errors.Wrap(err, "check the wait asked for")
		}
		if ok {
			r.reason = fmt.Sprintf("%s (%s)", resp.Status, a.why)
			r.rateLimited = a.rateLimit
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if a.wait > policy.askedWaitMax {
				return false, nil
			}
			r.asked, r.ok = a, true
			return true, nil
		}
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

func (r *retrier) backoff(waitMin, waitMax time.Duration, attemptNum int, _ *http.Response) time.Duration {
	var wait time.Duration
	switch {
	case !r.ok:
		// Without the response, as DefaultBackoff would otherwise follow the
		// Retry-After of a 429 or 503 however long it is. askedWait has
		// already followed what it could of that, within policy.askedWaitMax.
		wait = retryablehttp.DefaultBackoff(waitMin, waitMax, attemptNum, nil)
	case r.asked.unsaid:
		wait = rateLimitBackoff(attemptNum)
	default:
		wait = r.asked.wait
	}
	slog.Warn("Retry GitHub API request", slog.String("method", r.method), slog.String("url", r.url), slog.String("reason", r.reason), slog.Int("retry", attemptNum+1), slog.Duration("wait", wait))
	return wait
}

// rateLimitBackoff is the wait before retry attemptNum+1 of a rate limit that
// does not say how long to wait. GitHub asks for a wait that grows with each
// retry when such a limit persists. The random part keeps clients that were
// refused in the same second, as concurrent jobs of one repository are, from
// retrying together. Once a wait reaches policy.askedWaitMax it loses that
// part, but the clients no longer start it together by then.
func rateLimitBackoff(attemptNum int) time.Duration {
	wait := policy.rateLimitWait
	for range attemptNum {
		wait = min(2*wait, policy.askedWaitMax)
	}
	return min(wait+rand.N(policy.rateLimitWait), policy.askedWaitMax)
}

// ask is what a response asks of the retry of its request.
type ask struct {
	// wait is how long to wait, unless unsaid.
	wait time.Duration
	// unsaid tells a rate limit that does not say how long to wait, which is
	// waited for by rateLimitBackoff.
	unsaid bool
	// rateLimit tells a rate limit apart from a 503.
	rateLimit bool
	// why is what tells the wait, for the log.
	why string
}

// askedWait reports whether resp asks to be retried after a wait, and what it
// asks. A rate limit, answered with 403 or 429, asks for Retry-After, else
// until X-RateLimit-Reset when X-RateLimit-Remaining is 0, else does not say.
// A 503 asks for its Retry-After, if it has one. 403 also refuses a token that
// may not do what was asked, as GITHUB_TOKEN may not read GET /user, and that
// one is told apart by the headers and by the message of the body, which is
// put back for the caller.
//
// A wait longer than policy.askedWaitMax is cut to just over it before it
// becomes a time.Duration, which a value of centuries would overflow into a
// negative wait, retried at once.
func askedWait(resp *http.Response) (ask, bool, error) {
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
	default:
		return ask{}, false, nil
	}
	rateLimit := resp.StatusCode != http.StatusServiceUnavailable

	// GitHub sends Retry-After in seconds. A value that is not, such as an
	// HTTP date, is left for the headers below, and for a 503 to the backoff.
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n >= 0 {
		return ask{
			wait:      time.Duration(min(n, int(policy.askedWaitMax/time.Second)+1)) * time.Second,
			rateLimit: rateLimit,
			why:       fmt.Sprintf("retry-after: %d", n),
		}, true, nil
	}
	if !rateLimit {
		return ask{}, false, nil
	}

	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		why := "primary rate limit"
		if r := resp.Header.Get("X-RateLimit-Resource"); r != "" {
			why = fmt.Sprintf("primary rate limit of %s", r)
		}
		n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
		if err != nil {
			return ask{unsaid: true, rateLimit: true, why: why}, true, nil
		}
		reset := max(time.Until(time.Unix(n, 0)), 0)
		// A second on top of the reset, so that a clock a little behind
		// GitHub's does not retry before it, which also puts a wait cut to
		// policy.askedWaitMax over it.
		return ask{
			wait:      min(reset, policy.askedWaitMax) + time.Second,
			rateLimit: true,
			why:       fmt.Sprintf("%s, resets in %s", why, reset.Round(time.Second)),
		}, true, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return ask{unsaid: true, rateLimit: true, why: "rate limit"}, true, nil
	}

	bs, err := peekBody(resp)
	if err != nil {
		return ask{}, false, errors.Wrap(err, "peek body")
	}
	// "API rate limit exceeded for ..." for the primary rate limit and "You
	// have exceeded a secondary rate limit ..." for the secondary one.
	switch bs = bytes.ToLower(bs); {
	case bytes.Contains(bs, []byte("secondary rate limit")):
		return ask{unsaid: true, rateLimit: true, why: "secondary rate limit"}, true, nil
	case bytes.Contains(bs, []byte("rate limit")):
		return ask{unsaid: true, rateLimit: true, why: "rate limit"}, true, nil
	default:
		return ask{}, false, nil
	}
}

// peekBody reads the start of the body and puts it back in front of the rest,
// so that the body still reads whole.
func peekBody(resp *http.Response) ([]byte, error) {
	bs, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(bs), resp.Body), resp.Body}
	if err != nil {
		return nil, errors.Wrap(err, "read body")
	}
	return bs, nil
}

// describe tells what GitHub said about a request it refused: the status, the
// rate limit headers that are set, and the start of the body, which holds the
// reason, such as which rate limit was hit. The callers report the status
// alone, and a 403 reads the same for a token that may not do something and
// for a rate limit.
func describe(resp *http.Response) string {
	ss := []string{fmt.Sprintf("status: %q", resp.Status)}
	for _, h := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Resource"} {
		if v := resp.Header.Get(h); v != "" {
			ss = append(ss, fmt.Sprintf("%s: %q", strings.ToLower(h), v))
		}
	}
	bs, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		ss = append(ss, fmt.Sprintf("body: (read: %v)", err))
	} else {
		ss = append(ss, fmt.Sprintf("body: %q", bytes.TrimSpace(bs)))
	}
	return strings.Join(ss, ", ")
}

// CheckScopes reports whether the token is set and has the required scopes.
//
// The granted scopes are taken from the X-OAuth-Scopes header of the "GET /user" response. Apart from a
// GitHub App installation token, GitHub Packages only supports a personal access token (classic), so a
// token answering 200 while reporting no scopes is rejected as well.
//
// An installation token, GITHUB_TOKEN in GitHub Actions included, cannot access "GET /user" and gets 403
// instead, and its permissions for GitHub Packages are granted by the workflow rather than by scopes, so
// 403 is logged at Info and the check is skipped. A rate limit, which GitHub also answers with 403, is
// retried by Do, and one that persists through the retries fails the check with ErrRateLimited rather
// than skipping it. Any other unexpected status skips the check with a warning.
//
// Every endpoint returns X-OAuth-Scopes for a personal access token (classic), so a cheaper one such as
// "GET /rate_limit" would do for reading the scopes. "GET /user" is used because it is the only one that
// answers GITHUB_TOKEN with 403 instead of 200 without the header, which is what tells a token that cannot
// report its scopes apart from a classic token that reports none.
//
// ref. https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages
func CheckScopes(token string, required []string, opts ...Option) error {
	options := &options{}

	for _, o := range opts {
		o.apply(options)
	}

	if token == "" {
		return errors.New("token is not set. specify the --token flag or the GITHUB_TOKEN environment variable")
	}

	if len(required) == 0 {
		return nil
	}

	if err := Do(options.httpClient, http.MethodGet, fmt.Sprintf("%s/user", baseURL), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusOK:
			var granted []string
			for s := range strings.SplitSeq(resp.Header.Get("X-OAuth-Scopes"), ",") {
				if s := strings.TrimSpace(s); s != "" {
					granted = append(granted, s)
				}
			}

			missing := make([]string, 0, len(required))
			for _, r := range required {
				if !slices.ContainsFunc(granted, func(g string) bool {
					return g == r || slices.Contains(impliedScopes[g], r)
				}) {
					missing = append(missing, r)
				}
			}
			if len(missing) > 0 {
				return errors.Errorf("insufficient token scopes. missing: %q, required: %q, actual: %q. use a personal access token (classic) with the required scopes. ref. https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps, https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages", missing, required, granted)
			}

			return nil
		case http.StatusUnauthorized:
			return errors.New("token is invalid or expired")
		case http.StatusForbidden:
			// GITHUB_TOKEN in GitHub Actions gets "Resource not accessible by integration" here, and its
			// permissions for GitHub Packages come from the workflow rather than from scopes, so this is expected
			slog.Info("The token cannot fetch its scopes, skip checking the token scopes", slog.Int("status", resp.StatusCode))
			return nil
		default:
			slog.Warn("Failed to fetch the token scopes, skip checking the token scopes", slog.Int("status", resp.StatusCode))
			return nil
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}

	return nil
}
