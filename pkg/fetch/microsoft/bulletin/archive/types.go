package archive

// Archive holds the parsed content of a single Microsoft Security Bulletin
// archive page on Microsoft Learn. The page is split into its YAML
// frontmatter (a flat metadata map) and the rest of the page body kept
// as raw markdown so downstream extractors can interpret structure
// (sections, tables, lists) without re-parsing what the fetcher already
// chose to normalize.
type Archive struct {
	ID          string         `json:"id"`
	Year        string         `json:"year"`
	URL         string         `json:"url"`
	Frontmatter map[string]any `json:"frontmatter"`
	Body        string         `json:"body"`
}

// tocNode mirrors the recursive structure of Microsoft Learn's toc.json. A
// node carries an href and may nest further nodes under either Items or
// Children depending on the section.
type tocNode struct {
	Href     string     `json:"href"`
	Items    []*tocNode `json:"items"`
	Children []*tocNode `json:"children"`
}
