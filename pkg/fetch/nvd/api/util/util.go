package util

import (
	"bytes"
	"context"
	"io"
	"math"
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

	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}

func Backoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
			if sleep, ok := parseRetryAfterHeader(resp.Header["Retry-After"]); ok {
				return sleep
			}
			return time.Second * 30
		}
	}

	mult := math.Pow(2, float64(attemptNum)) * float64(min)
	sleep := time.Duration(mult)
	if float64(sleep) != mult || sleep > max {
		sleep = max
	}
	return sleep
}

var timeNow = time.Now

func parseRetryAfterHeader(headers []string) (time.Duration, bool) {
	if len(headers) == 0 || headers[0] == "" {
		return 0, false
	}
	header := headers[0]
	// Retry-After: 120
	if sleep, err := strconv.ParseInt(header, 10, 64); err == nil {
		if sleep > 0 {
			return time.Second * time.Duration(sleep), true
		}
		return time.Second * 30, true
	}

	// Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
	retryTime, err := time.Parse(time.RFC1123, header)
	if err != nil {
		return 0, false
	}
	if until := retryTime.Sub(timeNow()); until > 0 {
		return until, true
	}
	// date is in the past
	return 0, true
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
