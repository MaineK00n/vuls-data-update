package releaseinfo

// Page is one release-information page, as served.
//
// Nothing is read out of the tables here. Which column carries what varies
// between them -- a release history is keyed by Build, a hotpatch calendar by
// Month -- and the set is not fixed: Microsoft added "Update type" after these
// pages had run for years without it, and the same table has been served with a
// row holding one cell more than its header. Reading the columns apart belongs
// in extract, under golden tests, where a changed one is handled by rerunning
// against origin/ rather than by refetching a page whose older revisions are
// gone.
type Page struct {
	// URL is the page's own canonical link, taken from the stored HTML rather
	// than from the request, so raw/ stays derivable from origin/ alone.
	URL    string  `json:"url,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one table of a page, with the label it is filed under.
//
// The label is what names the release a table covers -- "Version 22H2 (OS build
// 19045)", "Windows Server 2016 (OS build 14393)". Microsoft marks it with
// <strong>, not a heading: all fourteen Windows 10 release histories sit under
// the single "Windows 10 release history" h2, so the heading is the same for
// every one of them and says nothing that tells them apart.
//
// It is stored for the release name, which nothing else on the page carries,
// and for nothing else. The build a table covers is in the Build column of
// every one of its rows, so a label Microsoft restyles costs the name and not
// the chain.
type Table struct {
	Label  string   `json:"label,omitempty"`
	Header []string `json:"header,omitempty"`
	Rows   [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, with the link it carries.
//
// The link is kept because it is the only per-KB address these pages give: the
// KB article cell is written <a href="https://support.microsoft.com/help/5120249">
// KB5120249</a>, and reading the cell as text alone would leave a KB record
// whose URL had to be built by hand from its number. It is resolved against the
// page's own address, so a relative one stays usable away from the page it was
// read on; the absolute ones these pages use are unchanged by that.
//
// Every cell carries it, not only the ones this source reads, because which
// cell holds the link is the table's business and not the reader's -- on the
// lifecycle tables it is the "Latest update" cell rather than a KB one.
type Cell struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
