package scom

// Article is one file of the docset, as served, with the tables read out of it.
//
// Nothing is read out of the cells here. The KB an update rollup ships as is
// written as a bare number linked to the support site, and the same column
// holds a GitHub release on the SCX agent's tables, so what a cell means is
// extract's to decide, under golden tests.
type Article struct {
	// Path is where the article lives in the docs repository, which is also
	// where its history is. It is taken from the request rather than from the
	// document, the document naming only its rendered address.
	Path   string  `json:"path,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one table of a file, with the heading it sits under.
//
// The heading is the component -- "Management Server (and other components*)",
// "Agent and Gateway", "SCX Agent" -- which each advance on their own build
// numbers under the one update rollup. Which product version they belong to is
// not in the file at all; it is the file's own path.
type Table struct {
	Heading string   `json:"heading,omitempty"`
	Header  []string `json:"header,omitempty"`
	Rows    [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, with the link it carries.
//
// The link is what identifies a KB here. The cell reads "5068304" with no KB in
// front of it, and the same column on the SCX agent's tables reads "v1.6.9-0"
// and links to a GitHub release, so it is the link that says whether a row
// names a KB at all.
type Cell struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
