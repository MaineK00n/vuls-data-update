package securityadvisories

// Advisory is one entry of the nginx security advisories page.
//
// The page carries no publication date and no per-advisory permalink, so the
// only identifier available is the vulnerability ID linked from the entry.
type Advisory struct {
	ID    string `json:"id"`
	Title string `json:"title"`

	// Severity is stored verbatim ("none", "minor", "low", "medium",
	// "major"). It is deliberately not validated against a closed
	// vocabulary: a new severity word is data drift, not a structural
	// change, and must not break the fetch of the whole page.
	Severity string `json:"severity"`

	// NotVulnerable and Vulnerable hold the comma separated version
	// expressions exactly as written ("1.31.3+", "0.9.6-1.31.2",
	// "nginx/Windows 0.7.52-1.3.0", "none", "all"). Interpreting them is
	// left to extract.
	NotVulnerable []string `json:"not_vulnerable,omitempty"`
	Vulnerable    []string `json:"vulnerable,omitempty"`

	References []Reference `json:"references,omitempty"`
	Patches    []Patch     `json:"patches,omitempty"`
}

// Reference is a link of an advisory entry, such as the F5 article or the
// mailing list announcement ("Advisory"), the CVE record ("CVE-yyyy-nnnn") or a
// CERT note ("VU#nnnnnn").
type Reference struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

// Patch is a patch download offered by an advisory entry. Note carries the
// parenthesized applicability remark shown after the links, if any, e.g.
// "(for 1.9.13-1.11.0)".
type Patch struct {
	URL          string `json:"url"`
	SignatureURL string `json:"signature_url,omitempty"`
	Note         string `json:"note,omitempty"`
}
