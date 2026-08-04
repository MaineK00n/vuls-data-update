package xml

import (
	"encoding/xml"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/pkg/errors"

	tomcatXML "github.com/MaineK00n/vuls-data-update/pkg/fetch/apache/tomcat/xml"
)

var cveIDPattern = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

// severityRatings are the ratings the Tomcat security team assigns. An entry
// header reads "<severity>: <title>", but four legacy entries put something
// else before the colon, so the prefix is only taken as a severity when it is
// one of these.
var severityRatings = []string{"Low", "Moderate", "Important", "High", "Critical"}

// entry is one vulnerability, recovered from the run of blocks a section
// holds. It has no counterpart element in the source.
type entry struct {
	CVEs             []string
	Severity         string
	Title            string
	Affects          string
	Description      []string
	Commits          []string
	ConnectorCommits []string
	Revisions        []string
	Bugs             []string
	References       []string
}

// entries groups a section's blocks into vulnerabilities. The source nests
// nothing — a section is a flat run of paragraphs, and where one vulnerability
// ends and the next begins is a layout convention rather than anything the
// document declares. An entry therefore starts at a block carrying a <strong>
// header together with a CVE, and every following block belongs to it.
//
// Blocks before the first header are returned as the section's notes, in an
// entry that carries nothing else. Sections holding no header at all — the
// page preamble and the table of contents — yield nothing.
func entries(s tomcatXML.Section) ([]entry, []string, error) {
	var (
		es    []entry
		notes []string
		cur   *entry
	)

	for _, b := range s.Blocks {
		p, err := parseBlock(b)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "parse %s block of section %q", b.Tag, s.Name)
		}

		if cves, ok := header(p); ok {
			severity, title := split(p.Strong)
			es = append(es, entry{
				CVEs:             cves,
				Severity:         severity,
				Title:            title,
				Commits:          p.Commits,
				ConnectorCommits: p.ConnectorCommits,
				Revisions:        p.Revisions,
				Bugs:             p.Bugs,
				References:       linkedURLs(p, cves),
			})
			cur = &es[len(es)-1]
			continue
		}

		// A block flattens to one line per <br/> or list item, each of which
		// stands on its own: the qualifier a <br/> appends to the "Affects:"
		// line ("Users who followed the security guidance to remove the
		// examples web application are not affected.") reads as its own
		// statement, as does every <li> of a preconditions list.
		lines := strings.Split(p.Text, "\n")
		if len(lines) == 1 && lines[0] == "" {
			continue
		}

		if cur == nil {
			notes = append(notes, lines...)
			continue
		}

		if affects, ok := strings.CutPrefix(lines[0], "Affects"); ok {
			if affects, ok := strings.CutPrefix(strings.TrimSpace(affects), ":"); ok {
				cur.Affects = strings.TrimSpace(affects)
				lines = lines[1:]
			}
		}
		cur.Description = append(cur.Description, lines...)

		cur.Commits = append(cur.Commits, p.Commits...)
		cur.ConnectorCommits = append(cur.ConnectorCommits, p.ConnectorCommits...)
		cur.Revisions = append(cur.Revisions, p.Revisions...)
		cur.Bugs = append(cur.Bugs, p.Bugs...)
		cur.References = append(cur.References, linkedURLs(p, nil)...)
	}

	return es, notes, nil
}

// header reports whether the block opens an entry, and with which CVEs. The
// <cve> children are authoritative; three legacy entries predate the tag and
// link the CVE with a plain anchor instead.
func header(p block) ([]string, bool) {
	if !p.HasStrong {
		return nil, false
	}
	if len(p.CVEs) > 0 {
		return p.CVEs, true
	}
	var cves []string
	for _, h := range p.Hrefs {
		if m := cveIDPattern.FindString(h); m != "" && !slices.Contains(cves, m) {
			cves = append(cves, m)
		}
	}
	return cves, len(cves) > 0
}

// linkedURLs drops the anchors that only restate a CVE the entry already
// records, so a legacy CVE link does not appear as a reference of its own.
func linkedURLs(p block, cves []string) []string {
	var rs []string
	for _, h := range p.Hrefs {
		if h == "" || slices.Contains(cves, cveIDPattern.FindString(h)) {
			continue
		}
		rs = append(rs, h)
	}
	return rs
}

// split separates the "<severity>: <title>" header. A prefix that is not one
// of the assigned ratings is left with the title rather than reported as a
// severity.
func split(strong string) (string, string) {
	if severity, title, ok := strings.Cut(strong, ":"); ok {
		if severity = strings.TrimSpace(severity); slices.Contains(severityRatings, severity) {
			return severity, strings.TrimSpace(title)
		}
	}
	return "", strings.TrimSpace(strong)
}

// block is a section child with its inline markup separated out.
//
// Every descendant's character data accumulates into Text, while the markup
// that carries data is collected by tag. CVEs are the one field restricted to
// top-level children: ten entry headers quote an earlier CVE inside their
// <strong> title (e.g. "Important: The fix for CVE-2026-29146 allowed the
// bypass of the EncryptInterceptor", itself CVE-2026-34486), and that quoted
// ID must not become one of the entry's own CVEs.
type block struct {
	// Text is the flattened content, whitespace-collapsed, one line per <br/>
	// or list item.
	Text string
	// Strong is the text of the top-level <strong>, present on entry headers
	// and on a handful of prose notes ("Note: All of conditions above must be
	// true ...").
	Strong           string
	HasStrong        bool
	CVEs             []string
	Bugs             []string
	Revisions        []string
	Commits          []string
	ConnectorCommits []string
	Hrefs            []string
}

// parseBlock flattens the markup the fetcher kept verbatim. The stored value
// is the element's inner XML, so it is wrapped to form a parseable fragment.
func parseBlock(b tomcatXML.Block) (block, error) {
	var (
		p        block
		sb       strings.Builder
		strongSB strings.Builder
		depth    int
		// strongDepth is the depth at which the top-level <strong> opened,
		// 0 when not inside one.
		strongDepth int
	)

	d := xml.NewDecoder(strings.NewReader("<block>" + b.XML + "</block>"))
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return block{}, errors.Wrap(err, "decode as xml")
		}

		switch t := tok.(type) {
		case xml.CharData:
			// The source hard-wraps prose, so its newlines are formatting, not
			// content. Flattening them here leaves <br/> and list items as the
			// only producers of a line break in the buffer.
			v := unwrap(string(t))
			sb.WriteString(v)
			if strongDepth > 0 {
				strongSB.WriteString(v)
			}
		case xml.StartElement:
			if t.Name.Local == "block" && depth == 0 {
				continue
			}
			depth++

			// <br/> and <li> are line structure at any nesting level; the rest
			// are only recognized as the block's own markup, not the title's.
			switch t.Name.Local {
			case "br", "li":
				sb.WriteString("\n")
				continue
			case "strong":
				if depth == 1 {
					p.HasStrong = true
					strongDepth = depth
				}
				continue
			}

			switch t.Name.Local {
			case "cve":
				// Restricted to top-level children — see the type comment.
				if depth > 1 {
					continue
				}
				v, err := elementText(d, t)
				if err != nil {
					return block{}, err
				}
				sb.WriteString(v)
				p.CVEs = append(p.CVEs, strings.TrimSpace(v))
				depth--
			case "bug":
				v, err := elementText(d, t)
				if err != nil {
					return block{}, err
				}
				sb.WriteString(v)
				p.Bugs = append(p.Bugs, strings.TrimSpace(v))
				depth--
			case "revlink":
				p.Revisions = append(p.Revisions, attr(t, "rev"))
			case "hashlink", "connectorshashlink":
				// Both elements are empty — the rendered page turns the hash
				// attribute into the link text — so without this the sentence
				// reads "This was fixed with commit .". They are kept apart
				// because they resolve against different repositories.
				h := attr(t, "hash")
				sb.WriteString(h)
				switch t.Name.Local {
				case "hashlink":
					p.Commits = append(p.Commits, h)
				default:
					p.ConnectorCommits = append(p.ConnectorCommits, h)
				}
			case "a":
				p.Hrefs = append(p.Hrefs, attr(t, "href"))
			}
		case xml.EndElement:
			if t.Name.Local == "block" && depth == 0 {
				continue
			}
			if strongDepth == depth {
				strongDepth = 0
			}
			depth--
		}
	}

	p.Text = collapse(sb.String())
	p.Strong = collapse(strongSB.String())

	return p, nil
}

// elementText consumes an element already opened as start and returns its text.
func elementText(d *xml.Decoder, start xml.StartElement) (string, error) {
	var v string
	if err := d.DecodeElement(&v, &start); err != nil {
		return "", errors.Wrapf(err, "decode <%s>", start.Name.Local)
	}
	return v, nil
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}

// unwrap replaces the source's line breaks with spaces, so that the only
// newlines left in a block buffer are the ones <br/> and <li> put there.
func unwrap(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

// collapse trims each line and squeezes runs of whitespace, preserving the
// line breaks parseBlock recorded.
func collapse(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if f := strings.Join(strings.Fields(l), " "); f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, "\n")
}
