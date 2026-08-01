package xml

import (
	"encoding/xml"
)

// Advisory mirrors one security-<branch>.xml page of the Apache Tomcat site
// source.
//
// The document declares its structure only down to the section: <document>,
// <properties> and <section name= rtext=> are elements with defined meaning,
// so they map to fields one for one. Everything inside a section is prose —
// the vulnerabilities are not elements, they are a layout convention over a
// flat run of paragraphs — so each child is kept verbatim as innerxml and
// interpreting it is left to the extractor. This is the same split
// pkg/fetch/gentoo makes, where GLSA's declared fields are typed and its
// <description>/<impact> bodies are innerxml.
type Advisory struct {
	Branch     string     `json:"branch,omitempty"`
	Properties Properties `json:"properties,omitzero"`
	Sections   []Section  `json:"sections,omitempty"`
}

type Properties struct {
	Author string `xml:"author" json:"author,omitempty"`
	Title  string `xml:"title" json:"title,omitempty"`
}

// Section is one <section> of the page body. Every section is kept, including
// the page preamble and the table of contents, which carry no vulnerability
// but are part of the document.
type Section struct {
	Name string `json:"name,omitempty"`
	// RText is the rtext attribute verbatim. Upstream writes it in several
	// shapes ("2026-07-08", "released 18 Aug 2011", "10 March 2021", "not yet
	// released", "beta, 11 Feb 2014") and omits it on older pages.
	RText  string  `json:"rtext,omitempty"`
	Blocks []Block `json:"blocks,omitempty"`
}

// Block is one direct child of a section, kept as it appears. Tag is almost
// always "p"; the rest are the <ul>/<ol> lists carrying attack preconditions,
// the <toc/> placeholder, and one <o> that is a typo for <p> upstream.
type Block struct {
	Tag   string            `json:"tag,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
	XML   string            `json:"xml,omitempty"`
}

// document is the root of the page.
type document struct {
	Properties Properties `xml:"properties"`
	Body       struct {
		Sections []Section `xml:"section"`
	} `xml:"body"`
}

// UnmarshalXML keeps every child element of the section, in document order,
// with its markup intact. encoding/xml cannot express "any child element" as
// a struct tag, so the token stream is walked by hand.
func (s *Section) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	s.Name = attr(start, "name")
	s.RText = attr(start, "rtext")

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			var v struct {
				XML string `xml:",innerxml"`
			}
			if err := d.DecodeElement(&v, &t); err != nil {
				return err
			}
			s.Blocks = append(s.Blocks, Block{
				Tag:   t.Name.Local,
				Attrs: attrs(t),
				XML:   v.XML,
			})
		case xml.EndElement:
			return nil
		}
	}
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func attrs(e xml.StartElement) map[string]string {
	if len(e.Attr) == 0 {
		return nil
	}
	m := make(map[string]string, len(e.Attr))
	for _, a := range e.Attr {
		m[a.Name.Local] = a.Value
	}
	return m
}
