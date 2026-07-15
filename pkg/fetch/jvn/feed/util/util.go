package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
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

// IsAlertURL reports whether rawURL points to a JPCERT-AT alert page — one whose
// path is "/at/<year>/...". Only alert pages carry a fetchable HTML title; the
// other JPCERT reference types the JVN feeds cite under source "JPCERT-AT" —
// weekly reports ("/wr/", plain-text with no .html rendering) and press releases
// ("/pr/", PDF) — do not, so callers skip them. The URL path is the only reliable
// discriminator here: the feeds' reference id / VulinfoID fields are inconsistent
// (often the alert title text or a bare number rather than "JPCERT-AT-yyyy-nnnn").
//
// A bare "/at/" prefix is not enough — the feeds also cite vendor advisory URLs
// with "/at/" as a path segment (e.g. ".../at/portals/..."); requiring a 4-digit
// year segment excludes them.
func IsAlertURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	rest, ok := strings.CutPrefix(u.Path, "/at/")
	if !ok {
		return false
	}
	year, _, ok := strings.Cut(rest, "/")
	if !ok {
		return false
	}
	_, err = time.Parse("2006", year)
	return err == nil
}

// FetchTitle returns the title of the JPCERT-AT alert page whose feed URL is
// rawURL. JVN feeds do not carry the title of referenced alert pages, so it is
// retrieved from the page itself. Older alerts are referenced as PGP-signed
// ".txt" files that carry no HTML title, so the ".html" rendering of the same
// alert is fetched instead.
//
// A missing or empty title is treated as an error so an unexpected page (e.g. a
// soft 404) is surfaced rather than silently omitted.
func FetchTitle(client *utilhttp.Client, rawURL string) (string, error) {
	u := strings.TrimSpace(rawURL)

	// Only a trailing ".txt" extension is the plain-text alert; never rewrite a
	// ".txt" that appears elsewhere in the URL (e.g. a path segment or query).
	if rest, ok := strings.CutSuffix(u, ".txt"); ok {
		u = fmt.Sprintf("%s.html", rest)
	}

	resp, err := client.Get(u)
	if err != nil {
		return "", errors.Wrap(err, "get")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "parse html")
	}

	title := strings.TrimSpace(doc.Find("title").First().Text())
	if title == "" {
		return "", errors.Errorf("empty or missing title in %s", u)
	}
	return title, nil
}
