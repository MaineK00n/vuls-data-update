package sqlbuild

// Article is one support article, as served, with the tables read out of it.
//
// Nothing is read out of the cells here. Which column carries what is the
// table's business, and Microsoft writes the same fact several ways across the
// eleven this article holds -- a service pack lives in the Service pack column
// on the older versions and in the Update column on the newer ones. Reading
// that apart belongs in extract, under golden tests, where a change is handled
// by rerunning against origin/ rather than by refetching an article whose older
// revisions are only in git.
type Article struct {
	// Path is where the article lives in the docs repository, which is also
	// where its history is. It is taken from the request rather than from the
	// document, the document naming only its rendered address.
	Path   string  `json:"path,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one table of an article, with the heading it sits under.
//
// The heading is the product version -- "SQL Server 2019", "SQL Server 2008 R2"
// -- and is the only place the article states it: the build number's first two
// components say 15.0 and 10.50, which is the same fact in a spelling nothing
// else uses.
type Table struct {
	Heading string   `json:"heading,omitempty"`
	Header  []string `json:"header,omitempty"`
	Rows    [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, with the link it carries.
//
// The link is kept because it is the only per-KB address the article gives: a
// Knowledge Base number is written [KB5102335](https://support.microsoft.com/help/5102335),
// and some are written [KB5054833](cumulativeupdate32.md) instead, pointing at
// a sibling article rather than at the KB. Both are stored as written; which of
// them is an address for the KB is extract's to decide.
type Cell struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
