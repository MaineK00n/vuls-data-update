package metasploit

import "time"

type Metasploit struct {
	Type        string      `json:"type,omitempty"`
	Name        string      `json:"name,omitempty"`
	FullName    string      `json:"full_name,omitempty"`
	Description string      `json:"description,omitempty"`
	Rank        int         `json:"rank,omitempty"`
	Published   *time.Time  `json:"published,omitempty"`
	Modified    *time.Time  `json:"modified,omitempty"`
	References  []Reference `json:"references,omitempty"`
}

type Reference struct {
	Name   string   `json:"name,omitempty"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url,omitempty"`
}
