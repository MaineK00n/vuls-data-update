package exchange

// Page is the Exchange Server build numbers and release dates, as served.
//
// Nothing is read out of the cells here. The KB an update ships as is not in a
// column at all -- it is the link on the product's name -- and what a build
// number means is decided by the table it sits in, so reading that apart belongs
// in extract, under golden tests.
type Page struct {
	// URL is the page's own canonical link, taken from the stored HTML rather
	// than from the request, so raw/ stays derivable from origin/ alone.
	URL    string  `json:"url,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one product version's build history, with the heading it sits under.
//
// The heading is what names the version: Exchange Server SE and Exchange Server
// 2019 are both 15.2, so the build number does not tell them apart and the
// tables have to be kept as Microsoft filed them.
type Table struct {
	Heading string   `json:"heading,omitempty"`
	Header  []string `json:"header,omitempty"`
	Rows    [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, with the link it carries.
//
// The link is the point of it. This page names no Knowledge Base column: the KB
// an update ships as is the link on its product name, so a cell read as text
// alone loses the only identifier the whole source is for.
type Cell struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
