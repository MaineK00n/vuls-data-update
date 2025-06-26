package v1

type CpeMatchItem struct {
	Cpe23URI string `json:"cpe23Uri"`
	CpeName  []struct {
		Cpe23URI string `json:"cpe23Uri"`
	} `json:"cpe_name"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
}
