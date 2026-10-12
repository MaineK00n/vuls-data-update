package sfb

// Page is the Skype for Business Server update history, as served.
//
// Nothing is read out of the cells here. Which product an update is for is the
// table it sits in rather than anything in the row, so reading that apart
// belongs in extract, under golden tests.
type Page struct {
	// URL is the page's own canonical link, taken from the stored HTML rather
	// than from the request, so raw/ stays derivable from origin/ alone.
	URL    string  `json:"url,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is one product's update history, with the heading it sits under.
//
// The heading is the only place the product is named. A row says "Cumulative
// Update 8, Hotfix 2" and leaves which product that is to the table it is in,
// and the page holds six such tables, from Lync Server 2010 to the Subscription
// Edition -- beside another ten listing tools and downloads that are not
// updates at all.
type Table struct {
	Heading string   `json:"heading,omitempty"`
	Header  []string `json:"header,omitempty"`
	Rows    [][]Cell `json:"rows,omitempty"`
}

// Cell is one cell, with the link it carries.
type Cell struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href,omitempty"`
}
