package logger

import (
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	"io"
	"os"
	"time"
)

// ✅ লগ ফাইল এবং কনসোলে লগিং সেটআপ
func init() {
	// Ensure the log directory exists.
	if err := os.MkdirAll("log/app", os.ModePerm); err != nil {
		fmt.Println("❌ Could not create log directory:", err)
	}

	fileName := fmt.Sprintf("log/app/app_%s.log", time.Now().Format("02-01-2006"))
	logFile, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("❌ Could not open log file:", err)
	}
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetLevel(log.LevelInfo)
	log.Info("🚀 Logger initialized successfully!")
}

// ✅ সাকসেস লগ প্রিন্ট করার ফাংশন
func Success(message string) {
	log.Info("✅ " + message)
}
func Error(message string, err error) {
	if err != nil {
		log.Error("❌ " + message + ": " + err.Error())
	} else {
		log.Error("❌ " + message)

	}
}
func Warning(message string) {
	log.Warn("⚠️ " + message)
}

func Debug(message string) {
	log.Debug("🐛 " + message)
}

func Info(message string) {
	log.Info("ℹ️ " + message)
}

func Fatal(message string) {
	log.Fatal("💥 " + message)
	os.Exit(1)
}

func Panic(message string) {
	log.Panic("💥 " + message)
	os.Exit(1)
}

func Println(message string) {
	log.Info("📝 " + message) // Use Info for general logging
}

func Printf(format string, args ...interface{}) {
	log.Info(fmt.Sprintf("📝 "+format, args...)) // Use Info for general logging

}
func Print(message string) {
	log.Info("📝 " + message) // Use Info for general logging
}
func PrintfWithLevel(level log.Level, format string, args ...interface{}) {
	switch level {
	case log.LevelInfo:
		log.Info(fmt.Sprintf("ℹ️ "+format, args...))
	case log.LevelError:
		log.Error(fmt.Sprintf("❌ "+format, args...))
	case log.LevelWarn:
		log.Warn(fmt.Sprintf("⚠️ "+format, args...))
	case log.LevelDebug:
		log.Debug(fmt.Sprintf("🐛 "+format, args...))
	default:
		log.Info(fmt.Sprintf("📝 "+format, args...)) // Default to Info for unknown levels
	}
}
