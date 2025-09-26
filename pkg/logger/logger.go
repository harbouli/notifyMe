package logger

import (
	"log"
	"os"
)

type Logger struct {
	*log.Logger
}

func New() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "[NotifyMe] ", log.LstdFlags|log.Lshortfile),
	}
}

func (l *Logger) Info(v ...interface{}) {
	l.SetPrefix("[NotifyMe] [INFO] ")
	l.Println(v...)
}

func (l *Logger) Error(v ...interface{}) {
	l.SetPrefix("[NotifyMe] [ERROR] ")
	l.Println(v...)
}

func (l *Logger) Debug(v ...interface{}) {
	l.SetPrefix("[NotifyMe] [DEBUG] ")
	l.Println(v...)
}

func (l *Logger) Warn(v ...interface{}) {
	l.SetPrefix("[NotifyMe] [WARN] ")
	l.Println(v...)
}
