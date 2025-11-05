package util_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nvdutil "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/util"
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

func TestCheckRetry(t *testing.T) {
	tests := []struct {
		name         string
		retry        int
		errRespCount int
		errResponse  *http.Response
		wantReqCount int
		wantErrorMsg string
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
			wantErrorMsg: "unexpected EOF",
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
				Body:       io.NopCloser(&errorReader{readError: errors.New("should not retry")}),
			},
			wantReqCount: 1,
			wantErrorMsg: "should not retry",
		},
		{
			name:         "1st: 403 Forbidden",
			retry:        1,
			errRespCount: 1,
			errResponse: &http.Response{
				Status:     fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)),
				StatusCode: http.StatusForbidden,
				Body:       http.NoBody,
			},
			wantReqCount: 1,
			wantErrorMsg: "unexpected HTTP status 403 Forbidden",
		},
		{
			name:         "1st: 429 Too Many Requests, 2nd: 200 OK",
			retry:        1,
			errRespCount: 1,
			errResponse: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"5"}},
				Body:       http.NoBody,
			},
			wantReqCount: 2,
		},
		{
			name:         "1st: 408 Request Timeout, 2nd: 200 OK",
			retry:        1,
			errRespCount: 1,
			errResponse: &http.Response{
				StatusCode: http.StatusRequestTimeout,
				Body:       http.NoBody,
			},
			wantReqCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeContent(w, r, "test.txt", time.Now(), bytes.NewReader([]byte("12345")))
			}))
			defer ts.Close()

			c := utilhttp.NewClient(utilhttp.WithClientRetryMax(tt.retry), utilhttp.WithClientRetryWaitMin(10*time.Millisecond), utilhttp.WithClientRetryWaitMax(20*time.Millisecond), utilhttp.WithClientCheckRetry(nvdutil.CheckRetry), utilhttp.WithClientHTTPClient(&http.Client{Transport: &roundTripper{errRespCount: tt.errRespCount, errResponse: tt.errResponse}}))
			resp, err := c.Get(ts.URL)
			if err != nil {
				if tt.wantErrorMsg == "" {
					t.Fatalf("unexpected error: %s", err)
				}
				if !strings.HasSuffix(err.Error(), tt.wantErrorMsg) {
					t.Errorf("err is not expected error, got: %+v, want: %+v", err, tt.wantErrorMsg)
				}
			} else {
				defer resp.Body.Close()

				if tt.wantErrorMsg != "" {
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

func TestBackoff(t *testing.T) {
	defer nvdutil.SetTimeNowFunc(func() time.Time {
		return time.Date(1999, time.December, 31, 23, 59, 57, 0, time.UTC)
	})()

	type args struct {
		min        time.Duration
		max        time.Duration
		attemptNum int
		resp       *http.Response
	}
	tests := []struct {
		name string
		args args
		want time.Duration
	}{
		{
			name: "403 Forbidden",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusForbidden},
			},
			want: 6 * time.Second,
		},
		{
			name: "429 Too Many Requests, no Retry-After",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusTooManyRequests},
			},
			want: 30 * time.Second,
		},
		{
			name: "429 Too Many Requests, Retry-After 0s",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"0"}}},
			},
			want: 30 * time.Second,
		},
		{
			name: "429 Too Many Requests, Retry-After 5s",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"5"}}},
			},
			want: 5 * time.Second,
		},
		{
			name: "503 Service Unavailable, Retry-After Fri, 31 Dec 1999 23:59:59 GMT",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Retry-After": []string{"Fri, 31 Dec 1999 23:59:59 GMT"}}},
			},
			want: 2 * time.Second,
		},
		{
			name: "503 Service Unavailable, Retry-After Fri, 31 Dec 1999 23:59:56 GMT",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Retry-After": []string{"Fri, 31 Dec 1999 23:59:56 GMT"}}},
			},
			want: 0 * time.Second,
		},
		{
			name: "408 Request Timeout",
			args: args{
				min:        6 * time.Second,
				max:        30 * time.Second,
				attemptNum: 0,
				resp:       &http.Response{StatusCode: http.StatusRequestTimeout},
			},
			want: 6 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nvdutil.Backoff(tt.args.min, tt.args.max, tt.args.attemptNum, tt.args.resp); got != tt.want {
				t.Errorf("Backoff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFullURL(t *testing.T) {
	type args struct {
		baseURL          string
		startIndex       int
		resultsPerPage   int
		lastModStartDate *time.Time
		lastModEndDate   *time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "no date",
			args: args{
				baseURL:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:     0,
				resultsPerPage: 1,
			},
			want: "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0",
		},
		{
			name: "lastModStartDate only",
			args: args{
				baseURL:          "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:       0,
				resultsPerPage:   1,
				lastModStartDate: func() *time.Time { t := time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC); return &t }(),
			},
			wantErr: true,
		},
		{
			name: "lastModEndDate only",
			args: args{
				baseURL:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:     0,
				resultsPerPage: 1,
				lastModEndDate: func() *time.Time { t := time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC); return &t }(),
			},
			wantErr: true,
		},
		{
			name: "date",
			args: args{
				baseURL:          "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:       0,
				resultsPerPage:   1,
				lastModStartDate: func() *time.Time { t := time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC); return &t }(),
				lastModEndDate:   func() *time.Time { t := time.Date(2024, time.April, 15, 1, 0, 0, 0, time.UTC); return &t }(),
			},
			want: "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModEndDate=2024-04-15T01:00:00.000%2B00:00&lastModStartDate=2024-04-15T00:00:00.000%2B00:00&resultsPerPage=1&startIndex=0",
		},
		{
			name: "date range exceed 120 days",
			args: args{
				baseURL:          "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:       0,
				resultsPerPage:   1,
				lastModStartDate: func() *time.Time { t := time.Date(2023, time.December, 16, 23, 59, 59, 999999999, time.UTC); return &t }(),
				lastModEndDate:   func() *time.Time { t := time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC); return &t }(),
			},
			wantErr: true,
		},
		{
			name: "end date is before start date",
			args: args{
				baseURL:          "https://services.nvd.nist.gov/rest/json/cves/2.0",
				startIndex:       0,
				resultsPerPage:   1,
				lastModStartDate: func() *time.Time { t := time.Date(2024, time.April, 15, 1, 0, 0, 0, time.UTC); return &t }(),
				lastModEndDate:   func() *time.Time { t := time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC); return &t }(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nvdutil.FullURL(tt.args.baseURL, tt.args.startIndex, tt.args.resultsPerPage, tt.args.lastModStartDate, tt.args.lastModEndDate)
			if (err != nil) != tt.wantErr {
				t.Errorf("FullURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FullURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
