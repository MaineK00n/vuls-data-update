package archive

// Archive holds the parsed content of a single Microsoft Security Bulletin
// archive page on Microsoft Learn. The page is split into its YAML
// frontmatter (a flat metadata map) and an ordered tree of body sections
// delimited by ATX headings.
type Archive struct {
	ID          string         `json:"id"`
	Year        string         `json:"year"`
	URL         string         `json:"url"`
	Frontmatter map[string]any `json:"frontmatter"`
	Sections    []Section      `json:"sections"`
}

// Section is one heading-delimited region of the bulletin body. Body holds
// the raw markdown lines between this heading and the next heading of equal
// or shallower depth; Children holds nested deeper-level subsections in
// source order. Raw markdown is preserved inside Body verbatim so that
// downstream consumers can recover formatting that the structural split
// alone does not capture.
type Section struct {
	Level    int       `json:"level"`
	Heading  string    `json:"heading"`
	Body     string    `json:"body,omitempty"`
	Children []Section `json:"children,omitempty"`
}

// tocNode mirrors the recursive structure of Microsoft Learn's toc.json. A
// node carries an href and may nest further nodes under either Items or
// Children depending on the section.
type tocNode struct {
	Href     string     `json:"href"`
	Items    []*tocNode `json:"items"`
	Children []*tocNode `json:"children"`
}
