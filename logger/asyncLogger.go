package logger

import (
	log_model "dms-accounting/models/log"
	"dms-accounting/types"
	"log"

	"gorm.io/gorm"
)

type AsyncLogger struct {
	db      *gorm.DB
	channel chan types.LogEntry
}

func NewAsyncLogger(db *gorm.DB) *AsyncLogger {
	return &AsyncLogger{
		db:      db,
		channel: make(chan types.LogEntry, 100), // Buffered channel to hold log entries
	}
}

func (logger *AsyncLogger) ProcessLog() {
	log.Println("Starting asynchronous logger...")

	for logEntry := range logger.channel {
		log.Printf("Processing log entry: %s %s", logEntry.Method, logEntry.URL)

		// Convert types.LogEntry to models.log.Log
		dbLog := log_model.Log{
			Method:          logEntry.Method,
			URL:             logEntry.URL,
			RequestBody:     logEntry.RequestBody,
			ResponseBody:    logEntry.ResponseBody,
			RequestHeaders:  logEntry.RequestHeaders,
			ResponseHeaders: logEntry.ResponseHeaders,
			StatusCode:      logEntry.StatusCode,
			CreatedAt:       logEntry.CreatedAt,
		}

		// Create new log entry in database
		if err := logger.db.Create(&dbLog).Error; err != nil {
			log.Printf("Failed to insert new log entry: %v", err)
		} else {
			log.Printf("Inserted new log entry: %s %s", dbLog.Method, dbLog.URL)
		}
	}
}

// Log pushes a log entry into the channel
func (logger *AsyncLogger) Log(entry types.LogEntry) {
	logger.channel <- entry
}
