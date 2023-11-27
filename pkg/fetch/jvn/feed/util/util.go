package util

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

func CheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	// JVN Feed returns unexpected EOF
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return true, errors.Wrap(err, "read all response body")
		}
		return false, errors.Wrap(err, "read all response body")
	}

	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}
