package util_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jvnutil "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

type errorReader struct {
	readError error
}

func (f *errorReader) Read([]byte) (int, error) {
	return 0, f.readError
}

type roundTripper struct {
	reqCount     int
	errRespCount int
	errResponse  *http.Response
}

// When HTTP request is issued, this RoundTripper returns errResponse as many times as errRespCount.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.reqCount++
	if rt.errRespCount > 0 {
		rt.errRespCount--
		return rt.errResponse, nil
	}
	return http.DefaultTransport.RoundTrip(req)
}

var errShouldNotRetry = errors.New("should not retry")

func TestCheckRetry(t *testing.T) {
	tests := []struct {
		name         string
		retry        int
		errRespCount int
		errResponse  *http.Response
		wantReqCount int
		wantError    error
	}{
		{
			name:         "No error",
			retry:        0,
			wantReqCount: 1,
		},
		{
			name:         "1st, 2nd: 200 OK, but Read() return unexpected EOF",
			retry:        1,
			errRespCount: 2,
			errResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&errorReader{readError: io.ErrUnexpectedEOF}),
			},
			wantReqCount: 2,
			wantError:    io.ErrUnexpectedEOF,
		},
		{
			name:         "1st: 200 OK, but Read() return unexpected EOF, 2nd: 200 OK, No error",
			retry:        1,
			errRespCount: 1,
			errResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&errorReader{readError: io.ErrUnexpectedEOF}),
			},
			wantReqCount: 2,
		},
		{
			name:         "1st: 200 OK, but Read() return not unexpected EOF",
			retry:        1,
			errRespCount: 1,
			errResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&errorReader{readError: errShouldNotRetry}),
			},
			wantReqCount: 1,
			wantError:    errShouldNotRetry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeContent(w, r, "test.txt", time.Now(), bytes.NewReader([]byte("12345")))
			}))
			// The fake RoundTripper below answers the request, so the server
			// only has to provide a reachable address.
			ts.Start()

			c := utilhttp.NewClient(utilhttp.WithClientRetryMax(tt.retry), utilhttp.WithClientRetryWaitMin(10*time.Millisecond), utilhttp.WithClientRetryWaitMax(20*time.Millisecond), utilhttp.WithClientCheckRetry(jvnutil.CheckRetry), utilhttp.WithClientHTTPClient(&http.Client{Transport: &roundTripper{errRespCount: tt.errRespCount, errResponse: tt.errResponse}}))
			resp, err := c.Get(ts.URL)
			if err != nil {
				if tt.wantError == nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if !errors.Is(err, tt.wantError) {
					t.Errorf("err is not expected error, got: %+v, want: %+v", err, tt.wantError)
				}
			} else {
				defer resp.Body.Close()

				if tt.wantError != nil {
					t.Fatal("expected error has not occurred")
				}
				bs, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if !bytes.Equal(bs, []byte("12345")) {
					t.Errorf("invalid response body. got: %v, want: %v", bs, []byte("12345"))
				}
			}

			rt, ok := c.HTTPClient.Transport.(*roundTripper)
			if !ok {
				t.Fatal("set unexpected round tripper")
			}
			if rt.reqCount != tt.wantReqCount {
				t.Errorf("request count, got: %d, want: %d", rt.reqCount, tt.wantReqCount)
			}
		})
	}
}

func TestIsAlertURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "at alert html", url: "https://www.jpcert.or.jp/at/2021/at210050.html", want: true},
		{name: "at alert txt", url: "http://www.jpcert.or.jp/at/2004/at040002.txt", want: true},
		{
			// A vendor advisory URL that merely contains "/at/" as a path segment
			// (not the "/at/<year>/" alert structure) must not be treated as one.
			name: "vendor /at/ path is skipped",
			url:  "http://assistenzatecnica.telecomitalia.it/at/portals/assistenzatecnica.portal?_nfpb=true",
			want: false,
		},
		{name: "weekly report is skipped", url: "http://www.jpcert.or.jp/wr/2004/wr043001.txt", want: false},
		{name: "press release is skipped", url: "http://www.jpcert.or.jp/pr/2007/pr070002.pdf", want: false},
		{name: "non-at path is skipped", url: "https://jvn.jp/vu/JVNVU95841181/index.html", want: false},
		{name: "empty is skipped", url: "  ", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jvnutil.IsAlertURL(tt.url); got != tt.want {
				t.Errorf("IsAlertURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestFetchTitle(t *testing.T) {
	tests := []struct {
		name string
		// path is requested against the production JPCERT host, which the
		// in-memory network routes to the test server; the file at that path
		// under testdata/fixtures is served.
		path      string
		want      string
		wantError bool
	}{
		{
			name: "happy path",
			path: "/at210050.html",
			want: "Apache Log4jの任意のコード実行の脆弱性（CVE-2021-44228）に関する注意喚起",
		},
		{
			// Older alerts are referenced as PGP-signed .txt files; the title is
			// fetched from the .html rendering (here the same fixture).
			name: "txt is fetched as html",
			path: "/at210050.txt",
			want: "Apache Log4jの任意のコード実行の脆弱性（CVE-2021-44228）に関する注意喚起",
		},
		{
			// A page without a <title> is treated as an error.
			name:      "no title element",
			path:      "/no_title.html",
			wantError: true,
		},
		{
			// A non-existent file makes ServeFile respond with 404.
			name:      "not found",
			path:      "/nonexistent.html",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", strings.TrimPrefix(r.URL.Path, "/")))
			}))

			got, err := jvnutil.FetchTitle(utilhttp.NewClient(utilhttp.WithClientRetryMax(0), utilhttp.WithClientHTTPClient(ts.Client())), "https://www.jpcert.or.jp"+tt.path)
			switch {
			case err != nil && !tt.wantError:
				t.Fatalf("unexpected error: %s", err)
			case err == nil && tt.wantError:
				t.Fatal("expected error has not occurred")
			default:
				if got != tt.want {
					t.Errorf("FetchTitle() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}
