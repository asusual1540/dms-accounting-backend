package types

import "time"

// LogEntry represents a log entry to be stored in the database
type LogEntry struct {
	ID              uint
	Method          string
	URL             string
	RequestBody     string
	ResponseBody    string
	RequestHeaders  string
	ResponseHeaders string
	StatusCode      int
	CreatedAt       time.Time
}
