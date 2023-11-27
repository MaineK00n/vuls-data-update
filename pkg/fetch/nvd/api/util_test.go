package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utilapi "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

// When Read() is called, this reader feturns error until #{errorCount} calls. It succeeeds after that.
type errorIOReadCloser struct {
	errorCount int
	readError  error
	readCount  *int
}

func (f *errorIOReadCloser) Read(p []byte) (int, error) {
	(*f.readCount)++
	if *f.readCount <= f.errorCount {
		return 0, f.readError
	} else {
		return len(p), io.EOF
	}
}

func (f *errorIOReadCloser) Close() error {
	return nil
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
			readCount := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqCount++
				http.ServeContent(w, r, "test.txt", time.Now(), bytes.NewReader([]byte("12345")))
			}))
			defer ts.Close()

			checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				resp.Body = &errorIOReadCloser{errorCount: tt.errorCount, readError: tt.readError, readCount: &readCount}
				return utilapi.CheckRetry(ctx, resp, err)
			}
			c := utilhttp.NewClient(utilhttp.WithClientRetryMax(2), utilhttp.WithClientRetryWaitMin(10*time.Millisecond), utilhttp.WithClientRetryWaitMax(20*time.Millisecond), utilhttp.WithClientCheckRetry(checkRetry))

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
