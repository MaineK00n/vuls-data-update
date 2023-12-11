package glsa

type GLSA struct {
	Identifiers      []string      `yaml:"identifiers" json:"identifiers,omitempty"`
	Identifier       string        `yaml:"identifier" json:"identifier,omitempty"`
	PackageSlug      string        `yaml:"package_slug" json:"package_slug,omitempty"`
	Title            string        `yaml:"title" json:"title,omitempty"`
	Description      string        `yaml:"description" json:"description,omitempty"`
	Date             string        `yaml:"date" json:"date,omitempty"`
	Pubdate          string        `yaml:"pubdate" json:"pubdate,omitempty"`
	AffectedRange    string        `yaml:"affected_range" json:"affected_range,omitempty"`
	FixedVersions    []interface{} `yaml:"fixed_versions" json:"fixed_versions,omitempty"`
	AffectedVersions string        `yaml:"affected_versions" json:"affected_versions,omitempty"`
	NotImpacted      string        `yaml:"not_impacted" json:"not_impacted,omitempty"`
	Credit           string        `yaml:"credit" json:"credit,omitempty"`
	Solution         string        `yaml:"solution" json:"solution,omitempty"`
	URLs             []string      `yaml:"urls" json:"urls,omitempty"`
	CWEIDs           []string      `yaml:"cwe_ids" json:"cwe_ids,omitempty"`
	UUID             string        `yaml:"uuid" json:"uuid,omitempty"`
	CVSSv2           string        `yaml:"cvss_v2" json:"cvss_v2,omitempty"`
	CVSSv3           string        `yaml:"cvss_v3" json:"cvss_v3,omitempty"`
	Links            []struct {
		Type string `yaml:"type" json:"type,omitempty"`
		URL  string `yaml:"url" json:"url,omitempty"`
	} `yaml:"links" json:"links,omitempty"`
	Versions []struct {
		Number string `yaml:"number" json:"number,omitempty"`
		Commit struct {
			Tags      []string `yaml:"tags" json:"tags,omitempty"`
			SHA       string   `yaml:"sha" json:"sha,omitempty"`
			Timestamp string   `yaml:"timestamp" json:"timestamp,omitempty"`
		} `yaml:"commit" json:"commit,omitempty"`
	} `yaml:"versions" json:"versions,omitempty"`
}
