package pull

import "time"

// Missing is missing, NotInRepository is notInRepository, and FullHash is
// fullHash. Some of what they do, such as how git fails on a repository it does
// not trust, what %+v prints of the error, or which names have the length of a
// SHA-256 hash, is hard to check through Pull.
//
// This file is only compiled into the test binary, so it is not part of the
// production API.
var (
	Missing         = missing
	NotInRepository = notInRepository
	FullHash        = fullHash
)

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
