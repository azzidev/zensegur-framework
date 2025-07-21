package zensframework

import "log"

func newLog() *log.Logger {
	return log.Default()
}
