package fedora

type releasePage struct {
	Releases    []release `json:"releases"`
	Page        int       `json:"page"`
	Pages       int       `json:"pages"`
	RowsPerPage int       `json:"rows_per_page"`
	Total       int       `json:"total"`
}

type release struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type advisoryPage struct {
	Updates []struct {
		Alias     string `json:"alias,omitempty"`
		Autokarma bool   `json:"autokarma,omitempty"`
		Autotime  bool   `json:"autotime,omitempty"`
		Bugs      []struct {
			BugID    int `json:"bug_id,omitempty"`
			Feedback []struct {
				BugID   int `json:"bug_id,omitempty"`
				Comment struct {
					ID               int `json:"id,omitempty"`
					Karma            int `json:"karma,omitempty"`
					KarmaCritpath    int `json:"karma_critpath,omitempty"`
					TestcaseFeedback []struct {
						CommentID int `json:"comment_id,omitempty"`
						Karma     int `json:"karma,omitempty"`
						Testcase  struct {
							ID   int    `json:"id,omitempty"`
							Name string `json:"name,omitempty"`
						} `json:"testcase,omitempty"`
						TestcaseID int `json:"testcase_id,omitempty"`
					} `json:"testcase_feedback,omitempty"`
					Text      string `json:"text,omitempty"`
					Timestamp string `json:"timestamp,omitempty"`
					UpdateID  int    `json:"update_id,omitempty"`
					User      struct {
						Avatar string  `json:"avatar,omitempty"`
						Email  *string `json:"email,omitempty"`
						Groups []struct {
							Name string `json:"name,omitempty"`
						} `json:"groups,omitempty"`
						ID     int    `json:"id,omitempty"`
						Name   string `json:"name,omitempty"`
						Openid string `json:"openid,omitempty"`
					} `json:"user,omitempty"`
					UserID int `json:"user_id,omitempty"`
				} `json:"comment,omitempty"`
				CommentID int `json:"comment_id,omitempty"`
				Karma     int `json:"karma,omitempty"`
			} `json:"feedback,omitempty"`
			Parent   bool    `json:"parent,omitempty"`
			Security bool    `json:"security,omitempty"`
			Title    *string `json:"title,omitempty"`
		} `json:"bugs,omitempty"`
		Builds []struct {
			Epoch     *int   `json:"epoch,omitempty"`
			NVR       string `json:"nvr,omitempty"`
			ReleaseID *int   `json:"release_id,omitempty"`
			Signed    bool   `json:"signed,omitempty"`
			Type      string `json:"type,omitempty"`
		} `json:"builds,omitempty"`
		CloseBugs bool `json:"close_bugs,omitempty"`
		Comments  []struct {
			BugFeedback []struct {
				Bug struct {
					BugID    int    `json:"bug_id,omitempty"`
					Parent   bool   `json:"parent,omitempty"`
					Security bool   `json:"security,omitempty"`
					Title    string `json:"title,omitempty"`
				} `json:"bug,omitempty"`
				BugID     int `json:"bug_id,omitempty"`
				CommentID int `json:"comment_id,omitempty"`
				Karma     int `json:"karma,omitempty"`
			} `json:"bug_feedback,omitempty"`
			ID               int `json:"id,omitempty"`
			Karma            int `json:"karma,omitempty"`
			KarmaCritpath    int `json:"karma_critpath,omitempty"`
			TestcaseFeedback []struct {
				CommentID int `json:"comment_id,omitempty"`
				Karma     int `json:"karma,omitempty"`
				Testcase  struct {
					ID   int    `json:"id,omitempty"`
					Name string `json:"name,omitempty"`
				} `json:"testcase,omitempty"`
				TestcaseID int `json:"testcase_id,omitempty"`
			} `json:"testcase_feedback,omitempty"`
			Text      string `json:"text,omitempty"`
			Timestamp string `json:"timestamp,omitempty"`
			UpdateID  int    `json:"update_id,omitempty"`
			User      struct {
				Avatar string  `json:"avatar,omitempty"`
				Email  *string `json:"email,omitempty"`
				Groups []struct {
					Name string `json:"name,omitempty"`
				} `json:"groups,omitempty"`
				ID     int    `json:"id,omitempty"`
				Name   string `json:"name,omitempty"`
				Openid string `json:"openid,omitempty"`
			} `json:"user,omitempty"`
			UserID int `json:"user_id,omitempty"`
		} `json:"comments,omitempty"`
		ContentType              *string `json:"content_type,omitempty"`
		Critpath                 bool    `json:"critpath,omitempty"`
		CritpathGroups           *string `json:"critpath_groups,omitempty"`
		DateApproved             *string `json:"date_approved,omitempty"`
		DateModified             *string `json:"date_modified,omitempty"`
		DatePushed               *string `json:"date_pushed,omitempty"`
		DateStable               *string `json:"date_stable,omitempty"`
		DateSubmitted            string  `json:"date_submitted,omitempty"`
		DateTesting              *string `json:"date_testing,omitempty"`
		DisplayName              string  `json:"display_name,omitempty"`
		FromTag                  *string `json:"from_tag,omitempty"`
		Karma                    int     `json:"karma,omitempty"`
		Locked                   bool    `json:"locked,omitempty"`
		MeetsTestingRequirements bool    `json:"meets_testing_requirements,omitempty"`
		Notes                    string  `json:"notes,omitempty"`
		Pushed                   bool    `json:"pushed,omitempty"`
		Release                  struct {
			Branch                 string  `json:"branch,omitempty"`
			CandidateTag           string  `json:"candidate_tag,omitempty"`
			ComposedByBodhi        bool    `json:"composed_by_bodhi,omitempty"`
			CreateAutomaticUpdates *bool   `json:"create_automatic_updates,omitempty"`
			DistTag                string  `json:"dist_tag,omitempty"`
			Eol                    *string `json:"eol,omitempty"`
			IDPrefix               string  `json:"id_prefix,omitempty"`
			LongName               string  `json:"long_name,omitempty"`
			MailTemplate           string  `json:"mail_template,omitempty"`
			Name                   string  `json:"name,omitempty"`
			OverrideTag            string  `json:"override_tag,omitempty"`
			PackageManager         string  `json:"package_manager,omitempty"`
			PendingSigningTag      string  `json:"pending_signing_tag,omitempty"`
			PendingStableTag       string  `json:"pending_stable_tag,omitempty"`
			PendingTestingTag      string  `json:"pending_testing_tag,omitempty"`
			StableTag              string  `json:"stable_tag,omitempty"`
			State                  string  `json:"state,omitempty"`
			TestingRepository      *string `json:"testing_repository,omitempty"`
			TestingTag             string  `json:"testing_tag,omitempty"`
			Version                string  `json:"version,omitempty"`
		} `json:"release,omitempty"`
		Request          *string `json:"request,omitempty"`
		RequireBugs      bool    `json:"require_bugs,omitempty"`
		RequireTestcases bool    `json:"require_testcases,omitempty"`
		Requirements     *string `json:"requirements,omitempty"`
		Severity         string  `json:"severity,omitempty"`
		StableDays       int     `json:"stable_days,omitempty"`
		StableKarma      int     `json:"stable_karma,omitempty"`
		Status           string  `json:"status,omitempty"`
		Suggest          string  `json:"suggest,omitempty"`
		TestCases        []struct {
			ID   int    `json:"id,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"test_cases,omitempty"`
		TestGatingStatus *string `json:"test_gating_status,omitempty"`
		Title            string  `json:"title,omitempty"`
		Type             string  `json:"type,omitempty"`
		URL              string  `json:"url,omitempty"`
		UnstableKarma    int     `json:"unstable_karma,omitempty"`
		Updateid         string  `json:"updateid,omitempty"`
		User             struct {
			Avatar string  `json:"avatar,omitempty"`
			Email  *string `json:"email,omitempty"`
			Groups []struct {
				Name string `json:"name,omitempty"`
			} `json:"groups,omitempty"`
			ID     int    `json:"id,omitempty"`
			Name   string `json:"name,omitempty"`
			Openid string `json:"openid,omitempty"`
		} `json:"user,omitempty"`
		VersionHash string `json:"version_hash,omitempty"`
	} `json:"updates"`
	Page           int  `json:"page"`
	Pages          int  `json:"pages"`
	RowsPerPage    int  `json:"rows_per_page"`
	Total          int  `json:"total"`
	Chrome         bool `json:"chrome"`
	DisplayUser    bool `json:"display_user"`
	DisplayRequest bool `json:"display_request"`
	Package        any  `json:"package"`
}

type Advisory struct {
	Alias     string  `json:"alias,omitempty"`
	Autokarma bool    `json:"autokarma,omitempty"`
	Autotime  bool    `json:"autotime,omitempty"`
	Bugs      []Bug   `json:"bugs,omitempty"`
	Builds    []Build `json:"builds,omitempty"`
	CloseBugs bool    `json:"close_bugs,omitempty"`
	Comments  []struct {
		BugFeedback []struct {
			Bug struct {
				BugID    int    `json:"bug_id,omitempty"`
				Parent   bool   `json:"parent,omitempty"`
				Security bool   `json:"security,omitempty"`
				Title    string `json:"title,omitempty"`
			} `json:"bug,omitempty"`
			BugID     int `json:"bug_id,omitempty"`
			CommentID int `json:"comment_id,omitempty"`
			Karma     int `json:"karma,omitempty"`
		} `json:"bug_feedback,omitempty"`
		ID               int `json:"id,omitempty"`
		Karma            int `json:"karma,omitempty"`
		KarmaCritpath    int `json:"karma_critpath,omitempty"`
		TestcaseFeedback []struct {
			CommentID int `json:"comment_id,omitempty"`
			Karma     int `json:"karma,omitempty"`
			Testcase  struct {
				ID   int    `json:"id,omitempty"`
				Name string `json:"name,omitempty"`
			} `json:"testcase,omitempty"`
			TestcaseID int `json:"testcase_id,omitempty"`
		} `json:"testcase_feedback,omitempty"`
		Text      string `json:"text,omitempty"`
		Timestamp string `json:"timestamp,omitempty"`
		UpdateID  int    `json:"update_id,omitempty"`
		User      struct {
			Avatar string  `json:"avatar,omitempty"`
			Email  *string `json:"email,omitempty"`
			Groups []struct {
				Name string `json:"name,omitempty"`
			} `json:"groups,omitempty"`
			ID     int    `json:"id,omitempty"`
			Name   string `json:"name,omitempty"`
			Openid string `json:"openid,omitempty"`
		} `json:"user,omitempty"`
		UserID int `json:"user_id,omitempty"`
	} `json:"comments,omitempty"`
	ContentType              *string `json:"content_type,omitempty"`
	Critpath                 bool    `json:"critpath,omitempty"`
	CritpathGroups           *string `json:"critpath_groups,omitempty"`
	DateApproved             *string `json:"date_approved,omitempty"`
	DateModified             *string `json:"date_modified,omitempty"`
	DatePushed               *string `json:"date_pushed,omitempty"`
	DateStable               *string `json:"date_stable,omitempty"`
	DateSubmitted            string  `json:"date_submitted,omitempty"`
	DateTesting              *string `json:"date_testing,omitempty"`
	DisplayName              string  `json:"display_name,omitempty"`
	FromTag                  *string `json:"from_tag,omitempty"`
	Karma                    int     `json:"karma,omitempty"`
	Locked                   bool    `json:"locked,omitempty"`
	MeetsTestingRequirements bool    `json:"meets_testing_requirements,omitempty"`
	Notes                    string  `json:"notes,omitempty"`
	Pushed                   bool    `json:"pushed,omitempty"`
	Release                  struct {
		Branch                 string  `json:"branch,omitempty"`
		CandidateTag           string  `json:"candidate_tag,omitempty"`
		ComposedByBodhi        bool    `json:"composed_by_bodhi,omitempty"`
		CreateAutomaticUpdates *bool   `json:"create_automatic_updates,omitempty"`
		DistTag                string  `json:"dist_tag,omitempty"`
		Eol                    *string `json:"eol,omitempty"`
		IDPrefix               string  `json:"id_prefix,omitempty"`
		LongName               string  `json:"long_name,omitempty"`
		MailTemplate           string  `json:"mail_template,omitempty"`
		Name                   string  `json:"name,omitempty"`
		OverrideTag            string  `json:"override_tag,omitempty"`
		PackageManager         string  `json:"package_manager,omitempty"`
		PendingSigningTag      string  `json:"pending_signing_tag,omitempty"`
		PendingStableTag       string  `json:"pending_stable_tag,omitempty"`
		PendingTestingTag      string  `json:"pending_testing_tag,omitempty"`
		StableTag              string  `json:"stable_tag,omitempty"`
		State                  string  `json:"state,omitempty"`
		TestingRepository      *string `json:"testing_repository,omitempty"`
		TestingTag             string  `json:"testing_tag,omitempty"`
		Version                string  `json:"version,omitempty"`
	} `json:"release,omitempty"`
	Request          *string `json:"request,omitempty"`
	RequireBugs      bool    `json:"require_bugs,omitempty"`
	RequireTestcases bool    `json:"require_testcases,omitempty"`
	Requirements     *string `json:"requirements,omitempty"`
	Severity         string  `json:"severity,omitempty"`
	StableDays       int     `json:"stable_days,omitempty"`
	StableKarma      int     `json:"stable_karma,omitempty"`
	Status           string  `json:"status,omitempty"`
	Suggest          string  `json:"suggest,omitempty"`
	TestCases        []struct {
		ID   int    `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"test_cases,omitempty"`
	TestGatingStatus *string `json:"test_gating_status,omitempty"`
	Title            string  `json:"title,omitempty"`
	Type             string  `json:"type,omitempty"`
	URL              string  `json:"url,omitempty"`
	UnstableKarma    int     `json:"unstable_karma,omitempty"`
	Updateid         string  `json:"updateid,omitempty"`
	User             struct {
		Avatar string  `json:"avatar,omitempty"`
		Email  *string `json:"email,omitempty"`
		Groups []struct {
			Name string `json:"name,omitempty"`
		} `json:"groups,omitempty"`
		ID     int    `json:"id,omitempty"`
		Name   string `json:"name,omitempty"`
		Openid string `json:"openid,omitempty"`
	} `json:"user,omitempty"`
	VersionHash string `json:"version_hash,omitempty"`
}

type Bug struct {
	BugID    int `json:"bug_id,omitempty"`
	Feedback []struct {
		BugID   int `json:"bug_id,omitempty"`
		Comment struct {
			ID               int `json:"id,omitempty"`
			Karma            int `json:"karma,omitempty"`
			KarmaCritpath    int `json:"karma_critpath,omitempty"`
			TestcaseFeedback []struct {
				CommentID int `json:"comment_id,omitempty"`
				Karma     int `json:"karma,omitempty"`
				Testcase  struct {
					ID   int    `json:"id,omitempty"`
					Name string `json:"name,omitempty"`
				} `json:"testcase,omitempty"`
				TestcaseID int `json:"testcase_id,omitempty"`
			} `json:"testcase_feedback,omitempty"`
			Text      string `json:"text,omitempty"`
			Timestamp string `json:"timestamp,omitempty"`
			UpdateID  int    `json:"update_id,omitempty"`
			User      struct {
				Avatar string  `json:"avatar,omitempty"`
				Email  *string `json:"email,omitempty"`
				Groups []struct {
					Name string `json:"name,omitempty"`
				} `json:"groups,omitempty"`
				ID     int    `json:"id,omitempty"`
				Name   string `json:"name,omitempty"`
				Openid string `json:"openid,omitempty"`
			} `json:"user,omitempty"`
			UserID int `json:"user_id,omitempty"`
		} `json:"comment,omitempty"`
		CommentID int `json:"comment_id,omitempty"`
		Karma     int `json:"karma,omitempty"`
	} `json:"feedback,omitempty"`
	Parent   bool     `json:"parent,omitempty"`
	Security bool     `json:"security,omitempty"`
	Title    *string  `json:"title,omitempty"`
	Bugzilla Bugzilla `json:"bugzilla,omitempty"`
}

type Build struct {
	Epoch     *int                 `json:"epoch,omitempty"`
	NVR       string               `json:"nvr,omitempty"`
	ReleaseID *int                 `json:"release_id,omitempty"`
	Signed    bool                 `json:"signed,omitempty"`
	Type      string               `json:"type,omitempty"`
	Package   map[string][]Package `json:"package,omitempty"`
	Module    *Module              `json:"module,omitempty"`
}

type Package struct {
	Name    string `json:"name,omitempty" xmlrpc:"name"`
	Epoch   *int   `json:"epoch,omitempty" xmlrpc:"epoch"`
	Version string `json:"version,omitempty" xmlrpc:"version"`
	Release string `json:"release,omitempty" xmlrpc:"release"`
	Arch    string `json:"arch,omitempty" xmlrpc:"arch"`
}

type build struct {
	ID    int `xmlrpc:"id"`
	Extra struct {
		TypeInfo struct {
			Module Module `xmlrpc:"module"`
		} `xmlrpc:"typeinfo"`
	} `xmlrpc:"extra"`
}

type Module struct {
	Name    string `json:"name,omitempty" xmlrpc:"name"`
	Stream  string `json:"stream,omitempty" xmlrpc:"stream"`
	Version string `json:"version,omitempty" xmlrpc:"version"`
	Context string `json:"context,omitempty" xmlrpc:"context"`
}

func (m Module) IsZero() bool {
	return m.Name == "" && m.Stream == "" && m.Version == "" && m.Context == ""
}

type archive struct {
	ID       int    `xmlrpc:"id"`
	Filename string `xmlrpc:"filename"`
}

type bugzilla struct {
	Bug struct {
		BugID        string   `xml:"bug_id"`
		Error        string   `xml:"error,attr"`
		Alias        string   `xml:"alias"`
		CreationTs   string   `xml:"creation_ts"`
		ShortDesc    string   `xml:"short_desc"`
		DeltaTs      string   `xml:"delta_ts"`
		BugStatus    string   `xml:"bug_status"`
		Resolution   string   `xml:"resolution"`
		BugFileLoc   string   `xml:"bug_file_loc"`
		Keywords     string   `xml:"keywords"`
		Priority     string   `xml:"priority"`
		BugSeverity  string   `xml:"bug_severity"`
		DependsOn    []string `xml:"dependson"`
		Blocked      []string `xml:"blocked"`
		ExternalBugs *struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
		} `xml:"external_bugs"`
		LongDesc []struct {
			Isprivate    string `xml:"isprivate,attr"`
			Commentid    string `xml:"commentid"`
			CommentCount string `xml:"comment_count"`
			Who          struct {
				Text string `xml:",chardata"`
				Name string `xml:"name,attr"`
			} `xml:"who"`
			BugWhen string `xml:"bug_when"`
			Thetext string `xml:"thetext"`
		} `xml:"long_desc"`
	} `xml:"bug"`
}

type Bugzilla struct {
	BugID        string     `json:"bug_id,omitempty"`
	Error        string     `json:"error,omitempty"`
	Alias        string     `json:"alias,omitempty"`
	CreationTs   string     `json:"creation_ts,omitempty"`
	ShortDesc    string     `json:"short_desc,omitempty"`
	DeltaTs      string     `json:"delta_ts,omitempty"`
	BugStatus    string     `json:"bug_status,omitempty"`
	Resolution   string     `json:"resolution,omitempty"`
	BugFileLoc   string     `json:"bug_file_loc,omitempty"`
	Keywords     string     `json:"keywords,omitempty"`
	Priority     string     `json:"priority,omitempty"`
	BugSeverity  string     `json:"bug_severity,omitempty"`
	DependsOn    []string   `json:"depends_on,omitempty"`
	Blocked      []Bugzilla `json:"blocked,omitempty"`
	ExternalBugs *struct {
		Text string `json:"text,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"external_bugs,omitempty"`
	LongDesc []struct {
		Isprivate    string `json:"isprivate,omitempty"`
		Commentid    string `json:"commentid,omitempty"`
		CommentCount string `json:"comment_count,omitempty"`
		Who          struct {
			Text string `json:"text,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"who,omitempty"`
		BugWhen string `json:"bug_when,omitempty"`
		Thetext string `json:"thetext,omitempty"`
	} `json:"long_desc,omitempty"`
}
