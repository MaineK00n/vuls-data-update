package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

func CheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	originalBody := resp.Body
	defer originalBody.Close()

	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	// NVD JSON API returns 403 in rate limit excesses, should retry.
	// Also, the API returns 408 infreqently.
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusRequestTimeout:
		return true, errors.Errorf("unexpected HTTP status %s", resp.Status)
	}

	// NVD API rarely fails to send whole response body and results in unexpected EOF.
	// Read whole body in advance, to let retryablehttp retry in case of errors.
	// TODO(shino): This is just a kludge, not optimal way, better/cleaner way is welcome.
	body, err := io.ReadAll(originalBody)
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return true, errors.Wrap(err, "read all response body")
		}
		return false, errors.Wrap(err, "read all response body")
	}

	return false, nil
}

func FullURL(baseURL string, startIndex, resultsPerPage int) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := u.Query()
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	u.RawQuery = q.Encode()
	return u.String(), nil
}
