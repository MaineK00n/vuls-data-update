package salsa

import (
	"bufio"
	"io"
	"strings"

	"github.com/pkg/errors"
)

// paragraph is a paragraph of a file in the deb822 format (deb822(5)), as the
// Release and Sources files of the archive are: its fields, by their names as
// the file spells them. The value of a field is the rest of its line after the
// colon, without the spaces and tabs around it, followed by each of its
// continuation lines as the file has it, after a newline. A multiline field
// whose first line is empty, such as the Files of a Sources paragraph, thus has
// a value starting with a newline: "\n <md5> <size> <name>" for one file.
type paragraph map[string]string

// field returns the value of the field name, whose case does not matter, as
// deb822 field names are not case-sensitive.
func (p paragraph) field(name string) (string, bool) {
	for k, v := range p {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// parseDeb822 reads the paragraphs of a deb822 file. Paragraphs are separated by
// empty lines, which may hold spaces and tabs, and the last needs none after
// it. A field is a line of its name, a colon and its value, followed by its
// continuation lines, which start with a space or a tab. Anything else is an
// error: a line that is none of these, a name with characters deb822 does not
// allow, a name the paragraph already has, and a comment, which only the
// debian/control of a source package may hold.
func parseDeb822(r io.Reader) ([]paragraph, error) {
	var (
		ps []paragraph
		p  paragraph
		// name is the field being read, the last of p, and lines the lines of
		// its value so far, which become its value once it ends.
		name  string
		lines []string
	)
	end := func() {
		if p != nil {
			p[name] = strings.Join(lines, "\n")
			ps = append(ps, p)
			p = nil
		}
	}

	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, errors.Wrapf(err, "read line %d", n)
		}
		if line == "" && err == io.EOF {
			break
		}
		line = strings.TrimSuffix(line, "\n")

		switch {
		case strings.Trim(line, " \t") == "":
			end()
		case line[0] == ' ' || line[0] == '\t':
			if p == nil {
				return nil, errors.Errorf("unexpected line %d. expected: %s, actual: %q", n, "a continuation line after a field", line)
			}
			lines = append(lines, line)
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				return nil, errors.Errorf("unexpected line %d. expected: %s, actual: %q", n, "a field, a continuation line or an empty line", line)
			}
			if !isFieldName(k) {
				return nil, errors.Errorf("unexpected field name on line %d. expected: %s, actual: %q", n, "US-ASCII characters other than control characters, space and colon, not starting with # or -", k)
			}
			if p == nil {
				p = make(paragraph)
			} else {
				p[name] = strings.Join(lines, "\n")
			}
			if _, ok := p.field(k); ok {
				return nil, errors.Errorf("unexpected field on line %d. expected: %s, actual: %q", n, "a field the paragraph does not have yet", k)
			}
			name, lines = k, []string{strings.Trim(v, " \t")}
		}

		if err == io.EOF {
			break
		}
	}
	end()

	return ps, nil
}

// isFieldName reports whether s can name a field of a deb822 paragraph: it is
// US-ASCII characters other than control characters, space and colon, and does
// not start with # or -.
func isFieldName(s string) bool {
	return s != "" && s[0] != '#' && s[0] != '-' && !strings.ContainsFunc(s, func(r rune) bool { return r < '!' || r > '~' || r == ':' })
}
