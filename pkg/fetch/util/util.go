package util

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls-data-update")
	return dir
}

func FetchURL(url string, retry int) ([]byte, error) {
	rc := retryablehttp.NewClient()
	rc.RetryMax = retry
	rc.Logger = nil

	resp, err := rc.Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "http get, url: %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Error request response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}

	return bs, nil
}

func FetchConcurrently(urls []string, concurrency, wait, retry int) ([][]byte, error) {
	return nil, nil
}
