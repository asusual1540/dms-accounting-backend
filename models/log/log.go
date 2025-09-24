package log

import (
	"time"
)

// Log represents an HTTP request/response log entry.
type Log struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Method          string    `gorm:"type:varchar(10);not null" json:"method"`
	URL             string    `gorm:"type:text;not null" json:"url"`
	RequestBody     string    `gorm:"type:text" json:"request_body"`
	RequestHeaders  string    `gorm:"type:text" json:"request_headers"`
	ResponseBody    string    `gorm:"type:text" json:"response_body"`
	ResponseHeaders string    `gorm:"type:text" json:"response_headers"`
	StatusCode      int       `gorm:"type:int" json:"status_code"`
	CreatedAt       time.Time `gorm:"autoCreateTime" json:"created_at"`
}

type ProcessingStatus string

const (
	ProcessingStatusPending   ProcessingStatus = "pending"
	ProcessingStatusRunning   ProcessingStatus = "running"
	ProcessingStatusCompleted ProcessingStatus = "completed"
	ProcessingStatusFailed    ProcessingStatus = "failed"
	ProcessingStatusCancelled ProcessingStatus = "cancelled"
)
