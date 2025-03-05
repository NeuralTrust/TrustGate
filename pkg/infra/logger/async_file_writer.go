package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AsyncFileWriter struct {
	writer  *bufio.Writer
	file    *os.File
	mu      sync.Mutex
	logChan chan []byte
	done    chan struct{}
}

func NewAsyncFileWriter(logFile string, bufferSize int) (*AsyncFileWriter, error) {
	safeLogFile := filepath.Clean(logFile)
	file, err := os.OpenFile(safeLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}

	writer := bufio.NewWriterSize(file, bufferSize)
	aw := &AsyncFileWriter{
		writer:  writer,
		file:    file,
		logChan: make(chan []byte, 1000),
		done:    make(chan struct{}),
	}

	go aw.processLogs()

	return aw, nil
}

func (aw *AsyncFileWriter) Write(p []byte) (n int, err error) {
	select {
	case aw.logChan <- append([]byte{}, p...):
		return len(p), nil
	default:
		return 0, nil
	}
}

func (aw *AsyncFileWriter) processLogs() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case logData := <-aw.logChan:
			aw.mu.Lock()
			_, err := aw.writer.Write(logData)
			if err != nil {
				fmt.Println("error writing log data to file", err)
			}
			aw.mu.Unlock()

		case <-ticker.C:
			aw.mu.Lock()
			_ = aw.writer.Flush()
			aw.mu.Unlock()

		case <-aw.done:
			aw.mu.Lock()
			_ = aw.writer.Flush()
			aw.mu.Unlock()
			return
		}
	}
}

func (aw *AsyncFileWriter) Close() {
	close(aw.done)
	_ = aw.file.Close()
}
