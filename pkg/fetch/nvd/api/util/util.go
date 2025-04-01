package util

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

func CheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return true, errors.Wrap(err, "read all response body")
		}
		return false, errors.Wrap(err, "read all response body")
	}

	_ = resp.Body.Close() //nolint:errcheck
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}

func FullURL(baseURL string, startIndex, resultsPerPage int, lastModStartDate, lastModEndDate *time.Time) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := u.Query()
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if lastModStartDate != nil || lastModEndDate != nil {
		if lastModStartDate == nil || lastModEndDate == nil {
			return "", errors.New("Both lastModStartDate and lastModEndDate are required when either is present")
		}
		if (*lastModEndDate).Before(*lastModStartDate) {
			return "", errors.New("end date is before start date")
		}
		if (*lastModEndDate).Sub(*lastModStartDate) > 120*24*time.Hour {
			return "", errors.New("Date range cannot exceed 120 days")
		}
		q.Set("lastModStartDate", lastModStartDate.Format("2006-01-02T15:04:05.000-07:00"))
		q.Set("lastModEndDate", lastModEndDate.Format("2006-01-02T15:04:05.000-07:00"))
	}
	u.RawQuery = strings.ReplaceAll(q.Encode(), "%3A", ":")
	return u.String(), nil
}
