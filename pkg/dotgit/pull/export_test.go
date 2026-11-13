package pull

// NotFound is notFound. Some of what it tells apart, such as a repository
// that cannot be read, is hard to bring about through Pull, which opens the
// repository itself before contains does.
//
// This file is only compiled into the test binary, so it is not part of the
// production API.
var NotFound = notFound
