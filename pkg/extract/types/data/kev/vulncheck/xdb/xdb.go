package xdb

import (
	"cmp"
	"time"
)

type XDB struct {
	XDBID       string    `json:"xdb_id,omitempty"`
	XDBURL      string    `json:"xdb_url,omitempty"`
	DateAdded   time.Time `json:"date_added,omitzero"`
	ExploitType string    `json:"exploit_type,omitempty"`
	CloneSSHURL string    `json:"clone_ssh_url,omitempty"`
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
