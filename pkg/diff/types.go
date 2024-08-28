package diff

type WholeDiff struct {
	RootID    string                `json:"id,omitempty"`
	Extracted map[string]Repository `json:"extracted,omitempty"`
	Raw       map[string]Repository `json:"raw,omitempty"`
}

type Repository struct {
	Commits CommitRange `json:"commit_range,omitempty"`
	Files   []FileDiff  `json:"files,omitempty"`
}

type CommitRange struct {
	Old        string `json:"old,omitempty"`
	New        string `json:"new,omitempty"`
	CompareURL string `json:"compare_url,omitempty"`
}

type Path struct {
	Old string `json:"old,omitempty"`
	New string `json:"new,omitempty"`
}

type URL struct {
	Old string `json:"old,omitempty"`
	New string `json:"new,omitempty"`
}

type FileDiff struct {
	Path Path   `json:"path,omitempty"`
	URL  URL    `json:"url,omitempty"`
	Diff string `json:"diff,omitempty"`
}
