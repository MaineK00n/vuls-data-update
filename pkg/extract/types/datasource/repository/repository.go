package repository

import (
	"cmp"
	"slices"
	"time"
)

type Repository struct {
	URL    string     `json:"url,omitempty"`
	Commit string     `json:"commit,omitempty"`
	Date   *time.Time `json:"date,omitempty"`

	// Builds names the builds of the programs that wrote the repository's
	// content, as "<program> <version>", in the order they wrote it. A raw
	// repository's are the ones its commit names in its trailers; an extracted
	// repository's start with the extractor, followed by any program that
	// rewrote its output. The order is the record, so it is never sorted.
	Builds []string `json:"builds,omitempty"`
}

func Compare(x, y Repository) int {
	return cmp.Or(
		cmp.Compare(x.URL, y.URL),
		cmp.Compare(x.Commit, y.Commit),
		slices.Compare(x.Builds, y.Builds),
	)
}
