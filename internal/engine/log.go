package engine

import (
	"io"
	"log"
)

// orDiscard is logger, or one that drops everything when the caller passed none.
func orDiscard(logger *log.Logger) *log.Logger {
	if logger == nil {
		return log.New(io.Discard, "", 0)
	}
	return logger
}
