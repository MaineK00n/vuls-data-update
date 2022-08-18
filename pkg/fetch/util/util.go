package util

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
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
	bar := pb.Full.Start(len(urls))
	for i := 0; i < concurrency; i++ {
		g.Go(func() error {
			for u := range urlChan {
				bs, err := FetchURL(u, retry)
				if err != nil {
					return err
				}
				select {
				case respChan <- bs:
					bar.Increment()
				case <-ctx.Done():
					return ctx.Err()
				}
				time.Sleep(time.Duration(wait) * time.Second)
			}
			return nil
		})
	}
	go func() {
		_ = g.Wait()
		bar.Finish()
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

func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
}

type IndexChunk struct {
	From, To int
}

func ChunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}
