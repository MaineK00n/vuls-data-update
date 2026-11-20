package pull

import "time"

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
