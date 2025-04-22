package logger

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type ConsoleHook struct{}

func NewConsoleHook() *ConsoleHook {
	return &ConsoleHook{}
}

func (h *ConsoleHook) Fire(entry *logrus.Entry) error {
	line, err := entry.Logger.Formatter.Format(entry)
	if err != nil {
		return err
	}
	fmt.Print(string(line))
	return nil
}

func (h *ConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
