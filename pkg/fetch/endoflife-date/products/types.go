package products

type Product struct {
	Title             string   `yaml:"title" json:"title"`
	Category          string   `yaml:"category" json:"category"` // enum: "app", "db", "device", "framework", "lang", "library", "os", "server-app", "service", "standard"
	Tags              *string  `yaml:"tags,omitempty" json:"tags,omitempty"`
	IconURL           *string  `yaml:"iconUrl,omitempty" json:"icon_url,omitempty"`
	Permalink         string   `yaml:"permalink" json:"permalink"`
	AlternateURLs     []string `yaml:"alternate_urls,omitempty" json:"alternate_urls,omitempty"`
	VersionCommand    *string  `yaml:"versionCommand,omitempty" json:"version_command,omitempty"`
	ReleasePolicyLink *string  `yaml:"releasePolicyLink,omitempty" json:"release_policy_link,omitempty"`
	CustomColumns     []struct {
		Property    string  `yaml:"property" json:"property"`
		Position    string  `yaml:"position" json:"position"` // enum: "after-release-column", "before-latest-column", "after-latest-column"
		Label       string  `yaml:"label" json:"label"`
		Description *string `yaml:"description,omitempty" json:"description,omitempty"`
		Link        *string `yaml:"link,omitempty" json:"link,omitempty"`
	} `yaml:"customColumns,omitempty" json:"custom_columns,omitempty"`
	Identifiers []struct {
		Repology *string `yaml:"repology,omitempty" json:"repology,omitempty"`
		CPE      *string `yaml:"cpe,omitempty" json:"cpe,omitempty"`
		PURL     *string `yaml:"purl,omitempty" json:"purl,omitempty"`
	} `yaml:"identifiers,omitempty" json:"identifiers,omitempty"`
	Auto *struct {
		Cumulative *bool `yaml:"cumulative,omitempty" json:"cumulative,omitempty"`
		Methods    []any `yaml:"methods" json:"methods"`
	} `yaml:"auto,omitempty" json:"auto,omitempty"`
	Releases []struct {
		ReleaseCycle       string         `yaml:"releaseCycle" json:"release_cycle"`
		Link               *string        `yaml:"link,omitempty" json:"link,omitempty"`
		ReleaseLabel       *string        `yaml:"releaseLabel" json:"release_label,omitempty"`
		EOLColumn          any            `yaml:"eolColumn" json:"eol_column,omitempty"`                   // string or bool
		EOL                any            `yaml:"eol" json:"eol,omitempty"`                                // string<date> or bool
		EOASColumn         any            `yaml:"eoasColumn" json:"eoas_column,omitempty"`                 // string or bool
		EOAS               any            `yaml:"eoas" json:"eoas,omitempty"`                              // string<date> or bool
		EOESColumn         any            `yaml:"eoesColumn" json:"eoes_column,omitempty"`                 // string or bool
		EOES               any            `yaml:"eoes" json:"eoes,omitempty"`                              // string<date> or bool
		DiscontinuedColumn any            `yaml:"discontinuedColumn" json:"discontinued_column,omitempty"` // string or bool
		Discontinued       any            `yaml:"discontinued" json:"discontinued,omitempty"`              // string<date> or bool
		ReleaseDateColumn  any            `yaml:"releaseDateColumn" json:"release_date_column,omitempty"`  // string or bool
		ReleaseDate        *string        `yaml:"releaseDate" json:"release_date,omitempty"`               // string<date>
		ReleaseColumn      any            `yaml:"releaseColumn" json:"release_column,omitempty"`           // string or bool
		Latest             *string        `yaml:"latest" json:"latest,omitempty"`
		LatestReleaseDate  *string        `yaml:"latestReleaseDate" json:"latest_release_date,omitempty"` // string<date>
		Extras             map[string]any `yaml:",inline,omitempty" json:"extras,omitempty"`
	} `yaml:"releases" json:"releases"`
	Extras map[string]any `yaml:",inline,omitempty" json:"extras,omitempty"`
}

type AutoMethodGit struct {
	Git          string  `yaml:"git" json:"git"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodNpm struct {
	Npm          string  `yaml:"npm" json:"npm"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodDockerHub struct {
	DockerHub    string  `yaml:"docker_hub" json:"docker_hub"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodDistroWatch struct {
	DistroWatch  string  `yaml:"distrowatch" json:"distrowatch"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodCustom struct {
	Custom string `yaml:"custom" json:"custom"`
}

type AutoMethodGitHubReleases struct {
	GitHubReleases string `yaml:"github_releases" json:"github_releases"`
	Regex          any    `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude   any    `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
}

type AutoMethodPyPI struct {
	PyPI         string  `yaml:"pypi" json:"pypi"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodMaven struct {
	Maven        string  `yaml:"maven" json:"maven"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}

type AutoMethodCGit struct {
	CGit         string  `yaml:"cgit" json:"cgit"`
	Regex        any     `yaml:"regex,omitempty" json:"regex,omitempty"`                 // string or []string
	RegexExclude any     `yaml:"regex_exclude,omitempty" json:"regex_exclude,omitempty"` // string or []string
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
}
