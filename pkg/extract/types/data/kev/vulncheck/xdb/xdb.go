package xdb

import (
	"cmp"
	"time"
)

type XDB struct {
	XDBID       string    `json:"xdbId,omitempty"`
	XDBURL      string    `json:"xdbUrl,omitempty"`
	DateAdded   time.Time `json:"dateAdded,omitzero"`
	ExploitType string    `json:"exploitType,omitempty"`
	CloneSSHURL string    `json:"cloneSSHUrl,omitempty"`
}

func Compare(x, y XDB) int {
	return cmp.Or(
		cmp.Compare(x.XDBID, y.XDBID),
		cmp.Compare(x.XDBURL, y.XDBURL),
		x.DateAdded.Compare(y.DateAdded),
		cmp.Compare(x.ExploitType, y.ExploitType),
		cmp.Compare(x.CloneSSHURL, y.CloneSSHURL),
	)
}
