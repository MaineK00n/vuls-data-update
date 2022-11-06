package util

import (
	"os"
	"path/filepath"

	"golang.org/x/exp/maps"
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

func DestDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		return filepath.Join(CacheDir(), "output")
	}
	destDir := filepath.Join(pwd, "output")
	if f, err := os.Stat(destDir); os.IsNotExist(err) || !f.IsDir() {
		return CacheDir()
	}
	return destDir
}

func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
}
