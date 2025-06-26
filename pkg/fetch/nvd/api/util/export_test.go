package util

import "time"

func SetTimeNowFunc(f func() time.Time) (resetFunc func()) {
	timeNow = f
	return func() {
		timeNow = time.Now
	}
}
