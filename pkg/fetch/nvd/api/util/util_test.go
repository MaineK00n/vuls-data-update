package util_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nvdutil "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

type errorIOReader struct {
	readError error
}

func (f *errorIOReader) Read([]byte) (int, error) {
	return 0, f.readError
}

func newFakeRoundTripper(errorCount int, readError error, reqCount *int) http.RoundTripper {
	return fakeRoundTripper{
		internal:   http.DefaultTransport,
		errorCount: errorCount,
		readError:  readError,
		reqCount:   reqCount,
	}
}

type fakeRoundTripper struct {
	internal   http.RoundTripper
	errorCount int
	readError  error
	reqCount   *int
}

// When HTTP request is issued, this RoundTripper returns errorneous response until #{errorCount} calls.
// It returns normal rosponse after #{errorCount}.
func (f fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	(*f.reqCount)++
	resp, err := f.internal.RoundTrip(req)
	if *f.reqCount <= f.errorCount {
		resp.Body.Close()
		resp.Body = io.NopCloser(&errorIOReader{readError: f.readError})
	}
	return resp, err
}

func TestCheckRetry(t *testing.T) {
	tests := []struct {
		name             string
		expectedReqCount int
		errorCount       int
		readError        error
		hasError         bool
	}{
		{
			name:             "No error",
			expectedReqCount: 1,
			errorCount:       0,
			readError:        nil,
			hasError:         false,
		},
		{
			name:             "unexpected EOF",
			expectedReqCount: 3,
			errorCount:       3,
			readError:        io.ErrUnexpectedEOF,
			hasError:         true,
		},
		{
			name:             "unexpected EOF but retry OK",
			expectedReqCount: 2,
			errorCount:       1,
			readError:        io.ErrUnexpectedEOF,
			hasError:         false,
		},
		{
			name:             "other error",
			expectedReqCount: 1,
			errorCount:       1,
			readError:        errors.New("Dummy error, should not retry"),
			hasError:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			reqCount := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeContent(w, r, "test.txt", time.Now(), bytes.NewReader([]byte("12345")))
			}))
			defer ts.Close()

			httpClient := &http.Client{Transport: newFakeRoundTripper(tt.errorCount, tt.readError, &reqCount)}
			c := utilhttp.NewClient(utilhttp.WithClientRetryMax(2), utilhttp.WithClientRetryWaitMin(10*time.Millisecond), utilhttp.WithClientRetryWaitMax(20*time.Millisecond), utilhttp.WithClientCheckRetry(nvdutil.CheckRetry), utilhttp.WithClientHTTPClient(httpClient))

			_, err := c.Get(ts.URL)

			if !tt.hasError {
				if err != nil {
					t.Errorf("error in c.Get, got: %d, want: no error", err)
				} else {
					return
				}
			}

			// tt.hasError == true, from here
			if err == nil {
				t.Error("No error in c.Get, but wanted")
			}

			if !errors.Is(err, tt.readError) {
				t.Errorf("wrong error, got: %+v, want: %+v", err, tt.readError)
			}
			if reqCount != tt.expectedReqCount {
				t.Errorf("request count, got: %d, want: %d", reqCount, tt.expectedReqCount)
			}
		})
	}
}
