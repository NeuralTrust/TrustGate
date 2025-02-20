package logger

import (
	"bufio"
	"os"
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
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
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
			aw.writer.Write(logData)
			aw.mu.Unlock()

		case <-ticker.C:
			aw.mu.Lock()
			aw.writer.Flush()
			aw.mu.Unlock()

		case <-aw.done:
			aw.mu.Lock()
			aw.writer.Flush()
			aw.mu.Unlock()
			return
		}
	}
}

func (aw *AsyncFileWriter) Close() {
	close(aw.done)
	_ = aw.file.Close()
}
