package util

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls-data-update")
	return dir
}

func SourceDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		return filepath.Join(CacheDir(), "source")
	}
	srcDir := filepath.Join(pwd, "source")
	if f, err := os.Stat(srcDir); os.IsNotExist(err) || !f.IsDir() {
		return CacheDir()
	}
	return srcDir
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
	g, ctx := errgroup.WithContext(context.Background())
	urlChan := make(chan string)
	go func() {
		defer close(urlChan)
		for _, u := range urls {
			urlChan <- u
		}
	}()

	respChan := make(chan []byte, len(urls))
	timeout := time.After(10 * 60 * time.Second)
	for i := 0; i < concurrency; i++ {
		g.Go(func() error {
			for u := range urlChan {
				bs, err := FetchURL(u, retry)
				if err != nil {
					return err
				}
				select {
				case respChan <- bs:
				case <-ctx.Done():
					return ctx.Err()
				case <-timeout:
					return errors.New("timeout")
				}
				time.Sleep(time.Duration(wait) * time.Second)
			}
			return nil
		})
	}
	go func() {
		_ = g.Wait()
		close(respChan)
	}()

	bss := make([][]byte, 0, len(urls))
	for r := range respChan {
		bss = append(bss, r)
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return bss, nil
}
