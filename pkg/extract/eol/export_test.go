package eol

import eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"

// WithEOL replaces the built-in EOL table. Tests inject a small fixture
// table so the golden files stay stable as the real table grows.
func WithEOL(eol map[string]map[string]map[string]eolTypes.EOL) Option {
	return eolOption(eol)
}

type eolOption map[string]map[string]map[string]eolTypes.EOL

func (e eolOption) apply(opts *options) {
	opts.eols = map[string]map[string]map[string]eolTypes.EOL(e)
}
