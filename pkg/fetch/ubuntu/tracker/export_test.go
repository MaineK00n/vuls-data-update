package tracker

// WithRepoURL replaces the URL of the Ubuntu CVE Tracker repository. Tests
// clone a fixture repository from the local filesystem instead of reaching
// the network.
func WithRepoURL(repoURL string) Option {
	return repoURLOption(repoURL)
}

type repoURLOption string

func (u repoURLOption) apply(opts *options) {
	opts.repoURL = string(u)
}
