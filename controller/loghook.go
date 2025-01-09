package controller

import (
	log "github.com/sirupsen/logrus"
)

// Custom hook to add global fields
type LogHook struct {
	Fields    log.Fields
	LogLevels []log.Level
}

// Fire is called for each log entry to add global fields
func (hook *LogHook) Fire(entry *log.Entry) error {
	for key, value := range hook.Fields {
		entry.Data[key] = value
	}
	return nil
}

// Levels defines on which log levels this hook should fire
func (hook *LogHook) Levels() []log.Level {
	return hook.LogLevels
}
