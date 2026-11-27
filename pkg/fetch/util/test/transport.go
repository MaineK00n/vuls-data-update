package test

import (
	"io"
	"net/http"
	"sync"
)

// CutBody is a transport that hands on the responses of Next, except that the
// body of the first one fails with Err once After bytes of it are read, as an
// HTTP/2 stream reset or a dropped connection partway through a body does. A
// fetch test sets it under its client to show that a body cut off partway is
// asked for again. Cut says whether the body failed, so the test can tell a
// retry from a cut that never happened because the body was shorter than After.
type CutBody struct {
	Next  http.RoundTripper
	After int
	Err   error

	mu      sync.Mutex
	wrapped bool
	cut     bool
}

func (t *CutBody) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.wrapped {
		t.wrapped = true
		resp.Body = &cutBody{ReadCloser: resp.Body, left: t.After, t: t}
	}
	return resp, nil
}

// Cut reports whether the first body has failed with Err.
func (t *CutBody) Cut() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cut
}

type cutBody struct {
	io.ReadCloser
	left int
	t    *CutBody
}

func (b *cutBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		b.t.mu.Lock()
		b.t.cut = true
		b.t.mu.Unlock()
		return 0, b.t.Err
	}
	if len(p) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= n
	return n, err
}
