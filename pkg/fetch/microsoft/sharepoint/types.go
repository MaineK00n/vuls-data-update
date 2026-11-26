package sharepoint

// Page is the SharePoint Server update history, as served.
//
// Nothing is read out of the cells here. What a cell means depends on the
// column it is in and on the other cells of its row -- the packages a row
// describes are named in one cell and their KBs in another, matched by
// position -- and reading that apart belongs in extract, under golden tests,
// where a change is handled by rerunning against origin/.
type Page struct {
	// URL is the page's own canonical link, taken from the stored HTML rather
	// than from the request, so raw/ stays derivable from origin/ alone.
	URL    string  `json:"url,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one product version's update history, with the heading it sits
// under. The heading is the only place the page names the version a table
// covers.
type Table struct {
	Heading string   `json:"heading,omitempty"`
	Header  []string `json:"header,omitempty"`
	Rows    [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, as a list of lines.
//
// A SharePoint cell holds a list, and it is not presentation: one row
// describes two packages at once -- a server and its language pack, or
// Foundation and Server on the older versions -- naming them one per line and
// their KBs one per line beside them, so that the two columns line up by
// position. Reading the cell as one string would leave "KB 5002894 KB 5002896"
// with nothing to say which package either belongs to.
type Cell struct {
	Lines []Line `json:"lines,omitempty"`
}

// Line is one line of a cell, with the link it carries.
type Line struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
