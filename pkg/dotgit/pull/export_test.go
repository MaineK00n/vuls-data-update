package pull

// NotFound is notFound. Some of what it tells apart, such as exit status 129,
// which git cat-file -e returns for an option, cannot be brought about through
// Pull, which does not ask contains about a name that begins with "-".
//
// This file is only compiled into the test binary, so it is not part of the
// production API.
var NotFound = notFound
