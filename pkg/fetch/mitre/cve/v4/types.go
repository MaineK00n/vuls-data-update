package v4

import "encoding/xml"

type root struct {
	XMLName                   xml.Name        `xml:"cve" json:"cve,omitzero"`
	Xmlns                     string          `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Xsi                       string          `xml:"xsi,attr" json:"xsi,omitempty"`
	NoNamespaceSchemaLocation string          `xml:"noNamespaceSchemaLocation,attr" json:"nonamespaceschemalocation,omitempty"`
	Item                      []Vulnerability `xml:"item" json:"item,omitempty"`
}

type Vulnerability struct {
	Name   string `xml:"name,attr" json:"name,omitempty"`
	Seq    string `xml:"seq,attr" json:"seq,omitempty"`
	Type   string `xml:"type,attr" json:"type,omitempty"`
	Status string `xml:"status" json:"status,omitempty"`
	Phase  *struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Date string `xml:"date,attr" json:"date,omitempty"`
	} `xml:"phase" json:"phase,omitempty"`
	Desc string `xml:"desc" json:"desc,omitempty"`
	Refs []struct {
		Text   string `xml:",chardata" json:"text,omitempty"`
		Source string `xml:"source,attr" json:"source,omitempty"`
		URL    string `xml:"url,attr" json:"url,omitempty"`
	} `xml:"refs>ref" json:"refs,omitempty"`
	Votes *struct {
		Modify *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"modify" json:"modify,omitempty"`
		Noop *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"noop" json:"noop,omitempty"`
		Reviewing *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"reviewing" json:"reviewing,omitempty"`
		Accept *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"accept" json:"accept,omitempty"`
		Reject *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"reject" json:"reject,omitempty"`
		Recast *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"recast" json:"recast,omitempty"`
		Revote *struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Count string `xml:"count,attr" json:"count,omitempty"`
		} `xml:"revote" json:"revote,omitempty"`
	} `xml:"votes" json:"votes,omitempty"`
	Comments []struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Voter string `xml:"voter,attr" json:"voter,omitempty"`
	} `xml:"comments>comment" json:"comments,omitempty"`
}
