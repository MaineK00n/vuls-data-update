package releaseinfo

import "time"

var (
	Chain      = chain
	IsBaseline = isBaseline
	Release    = release
)

type Update = update

// NewUpdate is a monthly update of Windows 11 24H2, the line chain orders by
// revision, then date, then KB number.
func NewUpdate(kbID string, revision int, date time.Time) Update {
	return update{
		kbID:     kbID,
		page:     "windows-11",
		release:  "Windows 11 Version 24H2",
		major:    26100,
		revision: revision,
		date:     date,
		letter:   "B",
		raw:      "raw/windows-11.json",
	}
}

// WithPage moves the update to another page, linking it from there by url.
func (u update) WithPage(page, url string) Update {
	u.page = page
	u.url = url
	return u
}
