package notice

type response struct {
	Notices      []Notice `json:"notices"`
	Limit        int      `json:"limit"`
	Offset       int      `json:"offset"`
	TotalResults int      `json:"total_results"`
}

type Notice struct {
	Cves []struct {
		ID         string   `json:"id"`
		NoticesIds []string `json:"notices_ids"`
	} `json:"cves"`
	CvesIds         []string `json:"cves_ids"`
	Description     string   `json:"description"`
	ID              string   `json:"id"`
	Instructions    string   `json:"instructions"`
	IsHidden        bool     `json:"is_hidden"`
	Published       string   `json:"published"`
	References      []string `json:"references"`
	RelatedNotices  []string `json:"related_notices"`
	ReleasePackages map[string][]struct {
		Channel     *string `json:"channel,omitempty"`
		Description *string `json:"description,omitempty"`
		IsSource    bool    `json:"is_source"`
		IsVisible   *bool   `json:"is_visible,omitempty"`
		Name        string  `json:"name"`
		PackageType *string `json:"package_type,omitempty"`
		Pocket      *string `json:"pocket,omitempty"`
		SourceLink  *string `json:"source_link,omitempty"`
		Version     string  `json:"version"`
		VersionLink *string `json:"version_link,omitempty"`
	}
	Releases []struct {
		Codename   string `json:"codename"`
		SupportTag string `json:"support_tag"`
		Version    string `json:"version"`
	} `json:"releases"`
	Summary string `json:"summary"`
	Title   string `json:"title"`
	Type    string `json:"type"`
}
