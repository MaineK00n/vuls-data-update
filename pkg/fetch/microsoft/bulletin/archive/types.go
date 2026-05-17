package archive

// Archive holds the raw markdown for a single Microsoft Security Bulletin
// archive page on Microsoft Learn.
type Archive struct {
	ID       string `json:"id"`
	Year     string `json:"year"`
	URL      string `json:"url"`
	Markdown string `json:"markdown"`
}

// bulletinRef identifies a single bulletin in the TOC by its (year, msid)
// pair, e.g. ("2017", "ms17-006").
type bulletinRef struct {
	Year string
	MSID string
}

// tocNode mirrors the recursive structure of Microsoft Learn's toc.json. A
// node carries an href and may nest further nodes under either Items or
// Children depending on the section.
type tocNode struct {
	Href     string     `json:"href"`
	Items    []*tocNode `json:"items"`
	Children []*tocNode `json:"children"`
}
