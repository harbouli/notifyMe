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
		Logger: log.New(os.Stdout, "[HEXAGON] ", log.LstdFlags|log.Lshortfile),
	}
}

func (l *Logger) Info(v ...interface{}) {
	l.SetPrefix("[HEXAGON] [INFO] ")
	l.Println(v...)
}

func (l *Logger) Error(v ...interface{}) {
	l.SetPrefix("[HEXAGON] [ERROR] ")
	l.Println(v...)
}

func (l *Logger) Debug(v ...interface{}) {
	l.SetPrefix("[HEXAGON] [DEBUG] ")
	l.Println(v...)
}

func (l *Logger) Warn(v ...interface{}) {
	l.SetPrefix("[HEXAGON] [WARN] ")
	l.Println(v...)
}