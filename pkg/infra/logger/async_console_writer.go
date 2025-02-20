package logger

import (
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
)

type AsyncConsoleHook struct {
	logChan chan string
	done    chan struct{}
	wg      sync.WaitGroup
}

func NewAsyncConsoleHook(bufferSize int) *AsyncConsoleHook {
	hook := &AsyncConsoleHook{
		logChan: make(chan string, bufferSize),
		done:    make(chan struct{}),
	}

	hook.wg.Add(1)
	go hook.processLogs()

	return hook
}

func (h *AsyncConsoleHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	select {
	case h.logChan <- line:
	default:
	}

	return nil
}

func (h *AsyncConsoleHook) processLogs() {
	defer h.wg.Done()

	for {
		select {
		case logEntry := <-h.logChan:
			fmt.Print(logEntry)

		case <-h.done:
			for len(h.logChan) > 0 {
				fmt.Print(<-h.logChan)
			}
			return
		}
	}
}

func (h *AsyncConsoleHook) Close() {
	close(h.done)
	h.wg.Wait()
}

func (h *AsyncConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
