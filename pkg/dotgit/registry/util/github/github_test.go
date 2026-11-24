package github_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

func TestDo(t *testing.T) {
	type response struct {
		Header http.Header `json:"header,omitempty"`
		Query  url.Values  `json:"query,omitempty"`
	}

	type args struct {
		method string
		apiurl string
		token  string
		fn     func(resp *http.Response) error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				method: http.MethodGet,
				apiurl: func() string {
					u, _ := url.Parse("https://api.github.com/")
					u = u.JoinPath("orgs", "vulsio", "packages", "container", "vuls-data-db", "versions")
					q := u.Query()
					q.Set("page", "1")
					q.Set("per_page", "100")
					u.RawQuery = q.Encode()
					return u.String()
				}(),
				token: "token",
				fn: func(resp *http.Response) error {
					var got response
					if err := json.UnmarshalRead(resp.Body, &got); err != nil {
						return err
					}

					expected := response{
						Header: http.Header{
							"Accept":               []string{"application/vnd.github+json"},
							"Accept-Encoding":      []string{"gzip"},
							"Authorization":        []string{"Bearer token"},
							"User-Agent":           []string{"Go-http-client/1.1"},
							"X-Github-Api-Version": []string{"2022-11-28"},
						},
						Query: url.Values{
							"page":     []string{"1"},
							"per_page": []string{"100"},
						},
					}

					if diff := cmp.Diff(expected, got); diff != "" {
						return fmt.Errorf("fn(). (-expected +got):\n%s", diff)
					}

					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				switch r.URL.Path {
				case "/orgs/vulsio/packages/container/vuls-data-db/versions":
					bs, err := json.Marshal(response{Header: r.Header, Query: r.URL.Query()})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					w.WriteHeader(http.StatusOK)
					if _, err := w.Write(bs); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				default:
					http.NotFound(w, r)
				}
			default:
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			}
		}))
		// The in-memory network routes api.github.com to the test server, so
		// the production API URL is used as-is.
		client := ts.Client()

		t.Run(tt.name, func(t *testing.T) {
			if err := github.Do(client, tt.args.method, tt.args.apiurl, tt.args.token, tt.args.fn); (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckScopes(t *testing.T) {
	// "unexpected response status" answers 500, which Do retries.
	t.Cleanup(github.ShortenRetryWaits(time.Millisecond))

	type args struct {
		token    string
		required []string
	}
	tests := []struct {
		name    string
		args    args
		status  int
		scopes  *string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages, github.ScopeDeletePackages},
			},
			status: http.StatusOK,
			scopes: new("delete:packages, gist, read:org, repo, workflow, write:packages"),
		},
		{
			name: "insufficient scopes",
			args: args{
				token:    "token",
				required: []string{github.ScopeWritePackages},
			},
			status:  http.StatusOK,
			scopes:  new("read:packages, repo"),
			wantErr: true,
		},
		{
			name: "no required scopes",
			args: args{
				token: "token",
			},
			status: http.StatusOK,
			scopes: new(""),
		},
		{
			name: "token has no scopes",
			args: args{
				token:    "token",
				required: []string{github.ScopeWritePackages},
			},
			status:  http.StatusOK,
			scopes:  new(""),
			wantErr: true,
		},
		{
			name: "scopes are not reported",
			args: args{
				token:    "token",
				required: []string{github.ScopeWritePackages},
			},
			status:  http.StatusOK,
			wantErr: true,
		},
		{
			name: "token is not set",
			args: args{
				required: []string{github.ScopeReadPackages},
			},
			status:  http.StatusOK,
			wantErr: true,
		},
		{
			name: "token is invalid",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages},
			},
			status:  http.StatusUnauthorized,
			wantErr: true,
		},
		{
			name: "scopes cannot be fetched",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages},
			},
			status: http.StatusForbidden,
		},
		{
			name: "unexpected response status",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages},
			},
			status: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/user":
					if tt.scopes != nil {
						w.Header().Set("X-OAuth-Scopes", *tt.scopes)
					}
					w.WriteHeader(tt.status)
				default:
					http.NotFound(w, r)
				}
			}))

			if err := github.CheckScopes(tt.args.token, tt.args.required, github.WithHTTPClient(ts.Client())); (err != nil) != tt.wantErr {
				t.Errorf("CheckScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDo_retry(t *testing.T) {
	t.Cleanup(github.ShortenRetryWaits(time.Millisecond))

	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })

	type response struct {
		status int
		header http.Header
		body   string
		// hangUp closes the connection instead of answering.
		hangUp bool
	}
	tests := []struct {
		name   string
		method string
		// responses are answered in turn, and the last one again once they
		// run out.
		responses    []response
		wantRequests int
		// wantWait is the least time Do takes, which tells that the wait asked
		// for is waited for. ShortenRetryWaits leaves the waits GitHub asks for
		// alone.
		wantWait time.Duration
		wantErr  bool
		// wantErrContains is a part of the error that tells what GitHub said.
		wantErrContains string
		// wantRateLimited tells that the error is github.ErrRateLimited.
		wantRateLimited bool
		// wantLog is a part of the log of the retries, which tells why a
		// request is retried.
		wantLog string
	}{
		{
			name:         "5xx, then success",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusBadGateway}, {status: http.StatusOK}},
			wantRequests: 2,
			wantLog:      `reason="502 Bad Gateway"`,
		},
		{
			name:         "5xx until the retries run out",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusInternalServerError}},
			wantRequests: 5,
			wantErr:      true,
		},
		{
			name:         "DELETE, 5xx, then success",
			method:       http.MethodDelete,
			responses:    []response{{status: http.StatusBadGateway}, {status: http.StatusNoContent}},
			wantRequests: 2,
		},
		{
			name:         "connection error, then success",
			method:       http.MethodGet,
			responses:    []response{{hangUp: true}, {status: http.StatusOK}},
			wantRequests: 2,
		},
		{
			name:         "429, then success",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusTooManyRequests}, {status: http.StatusOK}},
			wantRequests: 2,
		},
		{
			name:         "403 with Retry-After, then success",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusForbidden, header: http.Header{"Retry-After": []string{"1"}}}, {status: http.StatusOK}},
			wantRequests: 2,
			wantWait:     time.Second,
			wantLog:      `reason="403 Forbidden (retry-after: 1)"`,
		},
		{
			name:   "403 of the primary rate limit, then success",
			method: http.MethodGet,
			responses: []response{
				{status: http.StatusForbidden, header: http.Header{"X-Ratelimit-Remaining": []string{"0"}, "X-Ratelimit-Reset": []string{strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)}, "X-Ratelimit-Resource": []string{"core"}}},
				{status: http.StatusOK},
			},
			wantRequests: 2,
			// The second on top of the reset.
			wantWait: time.Second,
			wantLog:  `reason="403 Forbidden (primary rate limit of core, resets in 0s)"`,
		},
		{
			name:            "primary rate limit that resets later than the limit",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusForbidden, header: http.Header{"X-Ratelimit-Remaining": []string{"0"}, "X-Ratelimit-Reset": []string{strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)}}}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: `x-ratelimit-remaining: "0"`,
			wantRateLimited: true,
		},
		{
			name:            "primary rate limit that resets centuries later",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusForbidden, header: http.Header{"X-Ratelimit-Remaining": []string{"0"}, "X-Ratelimit-Reset": []string{"99999999999"}}}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: `x-ratelimit-reset: "99999999999"`,
			wantRateLimited: true,
		},
		{
			name:   "403 of the secondary rate limit without headers, then success",
			method: http.MethodGet,
			responses: []response{
				{status: http.StatusForbidden, body: `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`},
				{status: http.StatusOK},
			},
			wantRequests: 2,
			wantLog:      `reason="403 Forbidden (secondary rate limit)"`,
		},
		{
			name:         "403 of the secondary rate limit until the retries run out",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusForbidden, body: `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`}},
			wantRequests: 5,
			// The wait doubles with each retry: 1, 2, 4 and 8 ms.
			wantWait:        15 * time.Millisecond,
			wantErr:         true,
			wantErrContains: "secondary rate limit",
			wantRateLimited: true,
		},
		{
			name:            "403 that is not a rate limit",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusForbidden, body: `{"message":"Resource not accessible by integration"}`}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: "Resource not accessible by integration",
		},
		{
			name:            "rate limit that asks for a longer wait than the limit",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusForbidden, header: http.Header{"Retry-After": []string{"3600"}}, body: `{"message":"You have exceeded a secondary rate limit."}`}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: `retry-after: "3600"`,
			wantRateLimited: true,
		},
		{
			name:            "Retry-After too long for a time.Duration",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"10000000000"}}}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: `retry-after: "10000000000"`,
			wantRateLimited: true,
		},
		{
			name:         "503 with Retry-After, then success",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": []string{"1"}}}, {status: http.StatusOK}},
			wantRequests: 2,
			wantWait:     time.Second,
			wantLog:      `reason="503 Service Unavailable (retry-after: 1)"`,
		},
		{
			name:            "503 that asks for a longer wait than the limit",
			method:          http.MethodGet,
			responses:       []response{{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": []string{"3600"}}}},
			wantRequests:    1,
			wantErr:         true,
			wantErrContains: `retry-after: "3600"`,
		},
		{
			// An HTTP date is not followed. Were it, the test would wait an
			// hour.
			name:         "503 with Retry-After as an HTTP date, then success",
			method:       http.MethodGet,
			responses:    []response{{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": []string{time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}}}, {status: http.StatusOK}},
			wantRequests: 2,
		},
		{
			name:         "404",
			method:       http.MethodDelete,
			responses:    []response{{status: http.StatusNotFound}},
			wantRequests: 1,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var log bytes.Buffer
			slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))

			var requests int
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				res := tt.responses[min(requests, len(tt.responses)-1)]
				requests++

				if res.hangUp {
					conn, _, err := http.NewResponseController(w).Hijack()
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					if err := conn.Close(); err != nil {
						t.Errorf("close connection: %v", err)
					}
					return
				}

				for k, vs := range res.header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(res.status)
				if _, err := w.Write([]byte(res.body)); err != nil {
					t.Errorf("write body: %v", err)
				}
			}))

			start := time.Now()
			err := github.Do(ts.Client(), tt.method, "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions", "token", func(resp *http.Response) error {
				switch resp.StatusCode {
				case http.StatusOK, http.StatusNoContent:
					return nil
				default:
					return fmt.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusOK, http.StatusNoContent}, resp.StatusCode)
				}
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("Do() error = %v, want it to contain %q", err, tt.wantErrContains)
			}
			if got := errors.Is(err, github.ErrRateLimited); got != tt.wantRateLimited {
				t.Errorf("errors.Is(Do(), ErrRateLimited) = %t, want %t. error: %v", got, tt.wantRateLimited, err)
			}
			if !strings.Contains(log.String(), tt.wantLog) {
				t.Errorf("Do() logged %q, want it to contain %q", log.String(), tt.wantLog)
			}
			if requests != tt.wantRequests {
				t.Errorf("Do() sent %d requests, want %d", requests, tt.wantRequests)
			}
			if elapsed := time.Since(start); elapsed < tt.wantWait {
				t.Errorf("Do() took %s, want at least %s", elapsed, tt.wantWait)
			}
		})
	}
}

func TestRateLimitBackoff(t *testing.T) {
	tests := []struct {
		attemptNum int
		// The wait is in [wantMin, wantMax].
		wantMin, wantMax time.Duration
	}{
		{attemptNum: 0, wantMin: 1 * time.Minute, wantMax: 2*time.Minute - 1},
		{attemptNum: 1, wantMin: 2 * time.Minute, wantMax: 3*time.Minute - 1},
		{attemptNum: 2, wantMin: 4 * time.Minute, wantMax: 5 * time.Minute},
		{attemptNum: 3, wantMin: 5 * time.Minute, wantMax: 5 * time.Minute},
		{attemptNum: 100, wantMin: 5 * time.Minute, wantMax: 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("retry %d", tt.attemptNum+1), func(t *testing.T) {
			waits := make(map[time.Duration]struct{})
			for range 100 {
				got := github.RateLimitBackoff(tt.attemptNum)
				if got < tt.wantMin || got > tt.wantMax {
					t.Fatalf("RateLimitBackoff(%d) = %s, want in [%s, %s]", tt.attemptNum, got, tt.wantMin, tt.wantMax)
				}
				waits[got] = struct{}{}
			}
			// Clients refused together do not retry together.
			if tt.wantMin < tt.wantMax && len(waits) == 1 {
				t.Errorf("RateLimitBackoff(%d) waited %v every time, want a random part", tt.attemptNum, waits)
			}
		})
	}
}
