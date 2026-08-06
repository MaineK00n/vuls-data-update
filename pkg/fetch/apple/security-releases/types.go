package securityreleases

// List represents a security releases index page,
// e.g. https://support.apple.com/en-us/100100 and its archive pages.
type List struct {
	ID       string    `json:"id,omitempty"`
	URL      string    `json:"url,omitempty"`
	Title    string    `json:"title,omitempty"`
	Releases []Release `json:"releases,omitempty"`
}

// Release is a row of a security releases index page. Newer pages use a
// 3-column table (name, available for, release date), older pages use a plain
// list whose text after the link is kept as-is in Text.
type Release struct {
	Name         string   `json:"name,omitempty"`
	URL          string   `json:"url,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	AvailableFor string   `json:"available_for,omitempty"`
	ReleaseDate  string   `json:"release_date,omitempty"`
	Text         string   `json:"text,omitempty"`
}

// Advisory represents a per-release security content page,
// e.g. https://support.apple.com/en-us/128067.
type Advisory struct {
	ID       string    `json:"id,omitempty"`
	URL      string    `json:"url,omitempty"`
	Title    string    `json:"title,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

// Section is a heading-delimited region of an advisory page, e.g. the release
// itself ("macOS Tahoe 26.6") or "Additional recognition". Content before the
// first heading is kept in a section with an empty name.
type Section struct {
	Name    string  `json:"name,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
}

// Entry is a vulnerability entry in a section. Content before the first
// component heading (e.g. the "Released ..." note) is kept in an entry with an
// empty component. Each labeled paragraph is one slice element; some pages
// repeat the label block under a single component heading (e.g. the AirPort
// firmware advisories), in which case the elements of AvailableFor, Impact,
// Description and IDs line up block-wise. Newlines within an element come
// from <br> in the source.
//
// IDs holds the vulnerability reference paragraphs verbatim, in all their
// era-specific shapes: "CVE-2026-43819: credit" (current), "CVE-2015-7048 :
// credit" preceded by a standalone "CVE-ID" marker paragraph (2012-2015),
// "CVE-ID: CVE-2008-4309" inline label (2003-2010, also spelled "CVE ID:"
// and "CVE-IDs:"), bare pre-2005 candidate lines such as "CAN-2002-1383:
// Multiple Integer Overflows", and "WebKit Bugzilla: NNNNNN" lines. Markers
// and labels are deliberately not stripped here: interpreting them is the
// extract stage's job, and a repeated marker doubles as a block-boundary
// hint in repeated-label entries.
type Entry struct {
	Component    string   `json:"component,omitempty"`
	AvailableFor []string `json:"available_for,omitempty"`
	Impact       []string `json:"impact,omitempty"`
	Description  []string `json:"description,omitempty"`
	IDs          []string `json:"ids,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	Others       []string `json:"others,omitempty"`
}
