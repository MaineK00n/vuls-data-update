package util_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeContent(w, r, "test.txt", time.Now(), bytes.NewReader([]byte("12345")))
			}))
			defer ts.Close() //nolint:errcheck

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
				defer resp.Body.Close() //nolint:errcheck

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
