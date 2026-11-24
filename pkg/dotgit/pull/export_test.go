package pull

import "time"

// NotFound is notFound. Some of what it tells apart, such as exit status 129,
// which git cat-file -e returns for an option, cannot be brought about through
// Pull, which does not ask contains about a name that begins with "-".
//
// This file is only compiled into the test binary, so it is not part of the
// production API.
var NotFound = notFound

// WithRetryWait replaces the wait before the first retry of a layer whose
// download broke off, so that a test of the retry does not sleep for seconds.
//
// This file is only compiled into the test binary, so the knob is not part of
// the production API.
func WithRetryWait(wait time.Duration) Option {
	return retryWaitOption(wait)
}

type retryWaitOption time.Duration

func (w retryWaitOption) apply(opts *options) {
	opts.retryWait = time.Duration(w)
}
